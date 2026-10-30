// Client and verifier rules: Poseidon (circomlibjs), the issuer's Merkle tree, circuit inputs, policy forms and
// anchoring, the index counter, the root audit and grace rule, post checks and RLN recovery.
const path = require("path");
const crypto = require("crypto");
const { buildPoseidon } = require("circomlibjs");
const { keccak256, toUtf8Bytes } = require("ethers");

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n; // BN254 scalar field
const ROOT = path.join(__dirname, "..");
const mod = (a) => ((a % P) + P) % P;
function inv(a) {  // modular inverse by Fermat
  let r = 1n, b = mod(a), e = P - 2n;
  while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; }
  return r;
}
const randField = () => mod(BigInt("0x" + crypto.randomBytes(32).toString("hex")));
const postHash = (text) => mod(BigInt(keccak256(toUtf8Bytes(text))));
// Dates are day numbers counted from 1900-01-01, so every living person's birth date is non-negative and fits the
// circuit's 20-bit range checks (2^20 days reach past the year 4700). Epochs are hours since 1970 (the clock).
const DAY_1970 = 25567;  // days from 1900-01-01 to 1970-01-01
const EPOCH_HOURS = 1;   // protocol constant, shipped with the client: one epoch per hour
const dayNumber = (iso) => Math.floor(Date.parse(iso + "T00:00:00Z") / 86400000) + DAY_1970;
const dayOfEpoch = (epoch) => Math.floor((Number(epoch) * EPOCH_HOURS) / 24) + DAY_1970;
const epochOfDay = (day) => ((day - DAY_1970) * 24) / EPOCH_HOURS;
// the latest birth date of someone who is at least `years` old on day `day`, by calendar subtraction (a 29 February
// birthday counts from 1 March in common years, so the cutoff never admits anyone a day early)
function yearsBefore(day, years) {
  const d = new Date((day - DAY_1970) * 86400000), y = d.getUTCFullYear() - years, m = d.getUTCMonth();
  const c = new Date(Date.UTC(y, m, d.getUTCDate()));
  if (c.getUTCMonth() !== m) c.setUTCDate(0);  // 29 Feb in a common year: the cutoff is 28 Feb
  return Math.floor(c.getTime() / 86400000) + DAY_1970;
}

let _H = null;
async function hasher() {
  if (!_H) {
    const p = await buildPoseidon();
    _H = (...xs) => p.F.toObject(p(xs.map((v) => BigInt(v))));
  }
  return _H;
}

// Binary Poseidon tree with zero leaves; leaves can be set to 0 to revoke them. The levels are built once, bottom
// up (about one hash per leaf), on the first root() or path(); after that an insert or revocation updates only the
// leaf's path, so root() and path() cost O(depth).
class Tree {
  constructor(H, depth) {
    this.H = H; this.depth = depth; this.leaves = []; this.lv = null;
    this.zeros = [0n];
    for (let i = 0; i < depth; i++) this.zeros.push(H(this.zeros[i], this.zeros[i]));
  }
  insert(leaf) {
    if (this.leaves.length >= 2 ** this.depth) throw new Error("tree full");
    this.leaves.push(BigInt(leaf));
    if (this.lv) this._update(this.leaves.length - 1);
    return this.leaves.length - 1;
  }
  revoke(index) { this.leaves[index] = 0n; if (this.lv) this._update(index); }
  _update(i) {
    this.lv[0][i] = this.leaves[i];
    for (let l = 0, k = i; l < this.depth; l++, k = Math.floor(k / 2)) {
      const p = Math.floor(k / 2), cur = this.lv[l];
      this.lv[l + 1][p] = this.H(cur[2 * p] ?? this.zeros[l], cur[2 * p + 1] ?? this.zeros[l]);
    }
  }
  levels() {
    if (this.lv) return this.lv;
    const lv = [this.leaves.slice()];
    for (let l = 0; l < this.depth; l++) {
      const cur = lv[l], next = [];
      for (let i = 0; i < Math.ceil(cur.length / 2); i++)
        next.push(this.H(cur[2 * i] ?? this.zeros[l], cur[2 * i + 1] ?? this.zeros[l]));
      lv.push(next);
    }
    return (this.lv = lv);
  }
  root() { const lv = this.levels(); return lv[this.depth][0] ?? this.zeros[this.depth]; }
  path(index) {
    const lv = this.levels(), pathElements = [], pathIndex = [];
    for (let l = 0; l < this.depth; l++) {
      const i = Math.floor(index / 2 ** l);  // plain arithmetic: >>, ^ and & wrap at 2^31
      pathElements.push(lv[l][i % 2 === 0 ? i + 1 : i - 1] ?? this.zeros[l]);
      pathIndex.push(i % 2);
    }
    return { pathElements, pathIndex };
  }
}

// Credential issued by the platform: holder-bound leaf over the attributes.
function makeCredential(H, { secret, birthDate, accountCreated, verifiedHuman, schema, salt }) {
  const idCommitment = H(secret);
  const leaf = H(schema, idCommitment, birthDate, accountCreated, verifiedHuman, salt);
  return { secret, birthDate, accountCreated, verifiedHuman, schema, salt, idCommitment, leaf };
}

// Witness input for one post. policy = {community, ageCutoff, seniorityCutoff, baseLimit, verifiedBonus, seniorityBonus, mode}
function postInput(tree, index, cred, policy, epoch, text, messageId) {
  const { pathElements, pathIndex } = tree.path(index);
  return {
    secret: cred.secret, birthDate: cred.birthDate, accountCreated: cred.accountCreated,
    verifiedHuman: cred.verifiedHuman, salt: cred.salt, pathElements, pathIndex, messageId,
    root: tree.root(), schema: cred.schema, epoch, community: policy.community, x: postHash(text),
    ageCutoff: policy.ageCutoff, seniorityCutoff: policy.seniorityCutoff, baseLimit: policy.baseLimit,
    verifiedBonus: policy.verifiedBonus, seniorityBonus: policy.seniorityBonus, mode: policy.mode,
  };
}

// The benchmark workload, shared by every timing harness: a depth-d tree with 37 other members, one member of our
// circuit (verified, senior, adult; 18+ community in pseudonymous mode) or of the reference RLN v2 circuit (limit
// 10). Returns make(k), the k-th post's witness input; build all inputs before starting a timer.
const BENCH_DAY = dayNumber("2026-10-26");
function benchWorkload(H, name) {
  const depth = Number(name.match(/_d(\d+)/)[1]);
  const tree = new Tree(H, depth);
  for (let i = 0; i < 37; i++) tree.insert(randField());
  const community = postHash("community:general"), epoch = epochOfDay(BENCH_DAY);
  if (name.startsWith("vcrln")) {
    const pol = { community, ageCutoff: dayNumber("2008-10-26"), seniorityCutoff: BENCH_DAY - 30,
      baseLimit: 1, verifiedBonus: 4, seniorityBonus: 5, mode: 1 };
    const cred = makeCredential(tree.H, { secret: randField(), birthDate: dayNumber("1995-03-14"), accountCreated: dayNumber("2024-01-10"),
      verifiedHuman: 1, schema: tree.H(postHash("IC4 SocialAccountCredential v1")), salt: randField() });
    const idx = tree.insert(cred.leaf);
    return (k) => postInput(tree, idx, cred, pol, epoch, "bench post " + k, k % 10);
  }
  const s = randField(), idx = tree.insert(tree.H(tree.H(s), 10));
  return (k) => { const { pathElements, pathIndex } = tree.path(idx);
    return { identitySecret: s, userMessageLimit: 10, messageId: k % 10, pathElements, identityPathIndex: pathIndex,
      x: postHash("bench post " + k), externalNullifier: tree.H(BigInt(epoch), community) }; };
}

// Limit the circuit will compute for a credential under a policy (used by tests and the verifier model).
function limitFor(cred, policy) {
  const senior = cred.accountCreated <= policy.seniorityCutoff ? 1 : 0;
  return policy.baseLimit + policy.verifiedBonus * cred.verifiedHuman + policy.seniorityBonus * senior;
}

// A community is identified by the hash of its DID string, reduced to the field.
const communityId = (did) => postHash(did);

// Community policy form. The community anchors its hash as an attribute of its own DID; every member derives the
// policy of each epoch from it by the same rule. The form also names the issuer DID and the schema the community
// accepts, so neither can be chosen per member. Cutoffs: age in calendar years, seniority in days before the epoch's day.
// form = {did, issuer, schema, ageYears (null: no age gate), seniorityOffsetDays, baseLimit, verifiedBonus, seniorityBonus, mode}
const NO_AGE_GATE = (1 << 20) - 1;
// offsets a client accepts, fixed in the client release (not chosen by the community), so no community can probe
// members with ad hoc cutoffs
const MENU = { ageYears: [null, 13, 16, 18, 21], seniorityOffsetDays: [0, 7, 30, 90, 365] };
const FORM_KEYS = ["did", "issuer", "schema", "ageYears", "seniorityOffsetDays", "baseLimit", "verifiedBonus", "seniorityBonus", "mode"];
function policyFormHash(form) {
  return keccak256(toUtf8Bytes(JSON.stringify(FORM_KEYS.map((k) => [k, form[k] == null ? null : String(form[k])]))));
}
function policyForEpoch(form, epoch) {
  const day = dayOfEpoch(epoch);
  return { community: communityId(form.did), ageCutoff: form.ageYears == null ? NO_AGE_GATE : yearsBefore(day, form.ageYears),
    seniorityCutoff: day - form.seniorityOffsetDays, baseLimit: form.baseLimit, verifiedBonus: form.verifiedBonus,
    seniorityBonus: form.seniorityBonus, mode: form.mode };
}
const needInt = (x, what) => { if (!Number.isSafeInteger(x)) throw new Error("bad " + what); return x; };
const byLog = (a, b) => a.block - b.block || a.logIndex - b.logIndex;
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";
// The value of an ERC-1056 attribute at time `at`, from the identity's events, each with its block number, log index
// and block time: only events mined at or before `at` count, in log order, and the last of them for each value decides
// whether it is valid (validTo >= at, as ethr-did-resolver reads it; a revocation sets validTo to 0). An owner change
// to the zero address deactivates the DID. The anchor counts only if exactly one value is valid; with none or several,
// or after deactivation, the client refuses to post.
function anchoredValue(events, name, at) {
  needInt(at, "time");
  const evs = events.map((e) => {
    for (const k of ["block", "logIndex", "time"]) needInt(e[k], "event " + k);
    return e;
  }).filter((e) => e.time <= at).sort(byLog);
  const last = new Map();
  for (const e of evs) {
    if (e.kind === "owner" && String(e.owner).toLowerCase() === ZERO_ADDRESS) throw new Error("DID deactivated");
    if (e.kind !== "owner" && e.name === name) last.set(e.value, needInt(Number(e.validTo), "validTo"));
  }
  const valid = [...last].filter(([, validTo]) => validTo >= at).map(([v]) => v);
  if (valid.length !== 1) throw new Error(valid.length ? "several anchored values" : "no anchored value");
  return valid[0];
}
// The policy of epoch e is the value anchored POLICY_LEAD_S before e starts, read from a view of the chain that has
// passed that time (a safe or finalized block of the reader's own node), so client and verifier use one form for the
// whole epoch. A change affects the first epoch whose cutoff includes it; an anchor close to the boundary cannot be read
// differently by readers whose views lag.
const POLICY_LEAD_S = 600;
const epochStart = (epoch) => needInt(epoch, "epoch") * EPOCH_HOURS * 3600;
function policyAnchorOf(events, name, epoch, viewTime) {
  const at = epochStart(epoch) - POLICY_LEAD_S;
  if (needInt(viewTime, "view time") <= at) throw new Error("the chain view has not passed the policy time");
  return anchoredValue(events, name, at);
}
// Client rule: prove only under the anchored form, read from the DID it names, for the issuer and schema of the
// member's credential, with offsets from the client's menu and limit coefficients in [0, 255] (no field wrap-around).
function acceptPolicyForm(form, anchoredHash, sourceDid, cred = null) {
  if (policyFormHash(form) !== anchoredHash) return { ok: false, reason: "not anchored" };
  if (form.did !== sourceDid) return { ok: false, reason: "form names another DID" };
  if (!MENU.seniorityOffsetDays.includes(form.seniorityOffsetDays) || !MENU.ageYears.includes(form.ageYears ?? null))
    return { ok: false, reason: "offset not on menu" };
  if (![form.baseLimit, form.verifiedBonus, form.seniorityBonus].every((x) => Number.isInteger(x) && x >= 0 && x <= 255) || ![0, 1].includes(form.mode))
    return { ok: false, reason: "limit field out of range" };
  if (cred && (String(cred.issuer) !== String(form.issuer) || String(cred.schema) !== String(form.schema)))
    return { ok: false, reason: "issuer or schema not the anchored one" };
  return { ok: true };
}
// Verifier rule for roots, from the issuer's registry events in log order (block number, then log index): inside the
// window W, and once a revocation follows a root, that root is accepted only until the time of the first such
// revocation plus a grace period g. This covers every older root in the ring, not only the one the revocation
// replaced; the deadline is fixed by the first revocation after the root, so later revocations cannot extend it, and
// a root published in the same block as a revocation is ordered by log index, not by the shared block time.
// published = {block, logIndex} from auditRoots; revocations = [{block, logIndex, time}]; now = the time of the
// verifier's head block. Malformed input is refused, not accepted.
const logAfter = (a, b) => a.block > b.block || (a.block === b.block && a.logIndex > b.logIndex);
function rootAcceptable({ inWindow, published, revocations, now, g }) {
  try {
    if (inWindow !== true || !published || !Array.isArray(revocations)) return false;
    for (const x of [published, ...revocations]) { needInt(x.block, "block"); needInt(x.logIndex, "log index"); }
    revocations.forEach((r) => needInt(r.time, "time")); needInt(now, "now"); needInt(g, "g");
    const later = revocations.filter((r) => logAfter(r, published));
    if (!later.length) return true;
    const first = later.reduce((a, r) => (logAfter(a, r) ? r : a));
    return now < first.time + g;
  } catch (e) {
    return false;
  }
}
// Verifier audit of the issuer's registry log: replay LeavesAdded and LeavesRevoked in log order and keep, for each
// root, the latest position at which the published root equals the root of the replayed tree. A root that no event
// derives (leaves hidden from the log) never enters the map and is refused; an old root republished without the events
// that produce it keeps its earlier position, so a revocation after that position still expires it. Revocations that
// zero at least one leaf are returned for the grace rule.
// events = [{kind: "added" | "revoked", block, logIndex, time, leaves | indices, root}]
function auditRoots(H, depth, events) {
  const tree = new Tree(H, depth), published = new Map(), revocations = [], mismatched = [];
  for (const e of [...events].sort(byLog)) {
    for (const k of ["block", "logIndex", "time"]) needInt(e[k], "event " + k);
    if (!["added", "revoked"].includes(e.kind) || !Array.isArray(e.kind === "added" ? e.leaves : e.indices) || e.root == null)
      throw new Error("malformed registry event");
    let changed = false;
    if (e.kind === "added") e.leaves.forEach((l) => tree.insert(l));
    else e.indices.forEach((i) => {
      if (Number(i) >= tree.leaves.length) throw new Error("revoked index beyond the tree");
      if (tree.leaves[Number(i)] !== 0n) changed = true;
      tree.revoke(Number(i));
    });
    if (changed) revocations.push({ block: e.block, logIndex: e.logIndex, time: e.time });
    if (BigInt(e.root) === tree.root()) published.set(BigInt(e.root).toString(), { block: e.block, logIndex: e.logIndex });
    else mismatched.push({ block: e.block, logIndex: e.logIndex, root: BigInt(e.root).toString() });
  }
  return { published, revocations, mismatched, tree };
}

// Client state: the next unused message index per (epoch, community). Reusing an index reveals the secret, so:
//  - the state is created once, at enrollment (IndexCounter.init), and a fresh state cannot post in the epoch it was
//    created in or the next, so a reinstalled client or a newly added device never starts from 0 in an epoch whose
//    indices may be used, even with a clock one epoch behind; a state that is later missing or unreadable is
//    replaced the same way. The caller passes the epoch of an authenticated chain head checked against its clock;
//    a clock more than one epoch behind is outside what the state can detect;
//  - it is read and written under a lock file, written to a temporary file, flushed and renamed before the index is
//    returned; its shape is checked strictly, and transient read errors are retried before a state counts as lost;
//  - it records the highest epoch used and refuses an earlier one, so a clock set forward and back cannot prune a
//    used slot and hand out its indices again;
//  - epochs must be safe integers and communities canonical field elements, so one (epoch, community) has one slot;
//  - before an index is used, the caller can check the member's own nullifier for it against the community's whole
//    table, downloaded rather than queried per index (isUsed), which catches a state restored from an older copy if
//    the table is complete and honest.
// Device d of D uses only indices j = d (mod D); all devices of a member must use the same D, and D cannot change
// within an epoch (the state of one device cannot see another's). A retry of the same post gets
// the same index, which the verifier drops as a replay. Slots more than KEEP_EPOCHS old are pruned.
const KEEP_EPOCHS = 48;
const isPlain = (o) => o !== null && typeof o === "object" && !Array.isArray(o);
function validState(s) {
  if (!isPlain(s) || !isPlain(s.slots)) return false;
  for (const k of ["lostAt", "maxEpoch"]) if (!Number.isSafeInteger(s[k])) return false;
  for (const slot of Object.values(s.slots)) {
    if (!isPlain(slot) || !Number.isSafeInteger(slot.next) || slot.next < 0 || !Number.isSafeInteger(slot.devices) || slot.devices < 1
      || !isPlain(slot.posts) || !Object.values(slot.posts).every((j) => Number.isSafeInteger(j) && j >= 0)) return false;
  }
  return true;
}
const canonCommunity = (c) => {
  const v = BigInt(c);
  if (v < 0n || v >= P) throw new Error("community is not a field element");
  return v.toString();
};
class IndexCounter {
  constructor(file, device = 0, devices = 1) {
    if (!Number.isInteger(device) || !Number.isInteger(devices) || device < 0 || device >= devices) throw new Error("bad device number");
    this.file = file; this.device = device; this.devices = devices;
  }
  // `epoch` is the current epoch at enrollment; the new state posts from the epoch after next
  static init(file, epoch, device = 0, devices = 1) {
    needInt(epoch, "epoch");
    const c = new IndexCounter(file, device, devices);
    c._locked(() => {
      if (require("fs").existsSync(file)) throw new Error("counter state already exists");
      c._save({ slots: {}, lostAt: epoch + 1, maxEpoch: epoch });
    });
    return c;
  }
  _locked(fn) {
    const fs = require("fs"), lock = this.file + ".lock", until = Date.now() + 5000;
    let fd;
    for (;;) {
      try { fd = fs.openSync(lock, "wx"); break; } catch (e) {
        // EPERM/EACCES: on Windows a lock file that was just deleted can stay "delete pending" for a moment
        if (!["EEXIST", "EPERM", "EACCES"].includes(e.code) || Date.now() > until) throw new Error("counter is locked by another client");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    }
    try { return fn(); } finally { fs.closeSync(fd); fs.unlinkSync(lock); }
  }
  _read() {
    const fs = require("fs");
    for (let k = 0; ; k++) {
      try { return fs.readFileSync(this.file, "utf8"); } catch (e) {
        if (!["EBUSY", "EACCES", "EPERM"].includes(e.code) || k >= 4) throw e;
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 100);  // a scanner or sync client holds the file
      }
    }
  }
  _load(epoch) {
    const fs = require("fs"), lost = (why) => {
      this._save({ slots: {}, lostAt: epoch + 1, maxEpoch: epoch });
      return new Error(`counter state ${why}: not posting in this epoch or the next`);
    };
    if (!fs.existsSync(this.file)) throw lost("missing");
    let state;
    try { state = JSON.parse(this._read()); } catch (e) {
      if (["EBUSY", "EACCES", "EPERM"].includes(e.code)) throw new Error("counter state busy: try again");
      state = null;
    }
    if (!validState(state)) {
      fs.renameSync(this.file, this.file + ".unreadable");
      throw lost("unreadable");
    }
    return state;
  }
  _save(state) {
    const fs = require("fs"), tmp = this.file + ".tmp", fd = fs.openSync(tmp, "w", 0o600);
    try { fs.writeSync(fd, JSON.stringify(state)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
    fs.renameSync(tmp, this.file);
  }
  // isUsed(j): true if the member's nullifier for index j is already in the community's table for this epoch
  take(epoch, community, limit, text, isUsed = null) {
    needInt(epoch, "epoch"); needInt(limit, "limit");
    const key = `${epoch}:${canonCommunity(community)}`;
    return this._locked(() => {
      const state = this._load(epoch);
      if (epoch < state.maxEpoch) throw new Error("epoch earlier than one already used: not posting");
      if (epoch <= state.lostAt) throw new Error("counter state is new or was lost recently: not posting in this epoch or the next");
      state.maxEpoch = epoch;
      for (const k of Object.keys(state.slots)) if (Number(k.split(":")[0]) < epoch - KEEP_EPOCHS) delete state.slots[k];
      const slot = (state.slots[key] ??= { next: 0, devices: this.devices, posts: {} });
      if (slot.devices !== this.devices) throw new Error("device count changed within the epoch");
      const h = postHash(text).toString();
      if (slot.posts[h] != null) { this._save(state); return slot.posts[h]; }
      for (;;) {
        const j = this.device + this.devices * slot.next;
        if (j >= limit) { this._save(state); throw new Error("limit reached for this epoch and community"); }
        slot.next += 1;
        if (isUsed && isUsed(j)) continue;  // used by an earlier copy of this state: skip it
        slot.posts[h] = j;
        this._save(state);
        return j;
      }
    });
  }
}

// Community verifier, after the Groth16 proof and the root window have been checked (a post that fails either never
// reaches the nullifier table, so a forged share cannot make a member's genuine post look like a second one).
// `p` = pub(publicSignals); `seen` maps nullifier -> {x, y} for the current epoch. Returns {ok, reason, secret?}: a
// repeated (nullifier, x) is a replay and is dropped; a repeated nullifier with a new x means the member went over
// the limit, and the two shares give the secret to hand to the issuer. Malformed input is rejected, not thrown.
function checkPost(p, { schema, policy, epoch, text }, seen, { proofValid = false, rootAcceptable = false } = {}) {
  if (proofValid !== true) return { ok: false, reason: "proof" };
  if (rootAcceptable !== true) return { ok: false, reason: "root" };
  try {
    const want = { schema, epoch, community: policy.community, x: postHash(text), ageCutoff: policy.ageCutoff,
      seniorityCutoff: policy.seniorityCutoff, baseLimit: policy.baseLimit, verifiedBonus: policy.verifiedBonus,
      seniorityBonus: policy.seniorityBonus, mode: policy.mode };
    for (const [k, v] of Object.entries(want)) if (p[k] !== BigInt(v)) return { ok: false, reason: "public input " + k };
    const prev = seen.get(p.nullifier);
    if (prev && prev.x === p.x) return { ok: false, reason: "replay" };
    if (prev) return { ok: false, reason: "over limit", secret: recoverSecret(prev.x, prev.y, p.x, p.y) };
    seen.set(p.nullifier, { x: p.x, y: p.y });
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: "malformed" };
  }
}

// The member's own nullifier for index j in (epoch, community), as the circuit computes it: H(H(s, H(e, c), j)). A
// client looks it up in the community's table before using j (IndexCounter.take, isUsed).
const nullifierOf = (H, secret, epoch, community, j) => H(H(secret, H(BigInt(epoch), BigInt(community)), BigInt(j)));

// Two shares with the same nullifier and different x reveal the secret.
function recoverSecret(x1, y1, x2, y2) {
  if (mod(BigInt(x1)) === mod(BigInt(x2))) throw new Error("same x: the two shares are one post, no secret to recover");
  const a1 = mod((mod(BigInt(y2)) - mod(BigInt(y1))) * inv(mod(BigInt(x2)) - mod(BigInt(x1))));
  return mod(BigInt(y1) - a1 * BigInt(x1));
}

const art = (name) => ({
  wasm: path.join(ROOT, "build", name, "c_js", "c.wasm"),
  zkey: path.join(ROOT, "build", name, "c.zkey"),
  vkey: require(path.join(ROOT, "build", name, "vkey.json")),
});

// snarkjs public-signal order: outputs (y, nullifier, pseudonym) then public inputs in declaration order
const PUB = ["y", "nullifier", "pseudonym", "root", "schema", "epoch", "community", "x", "ageCutoff",
  "seniorityCutoff", "baseLimit", "verifiedBonus", "seniorityBonus", "mode"];
const pub = (signals) => {
  if (!Array.isArray(signals) || signals.length !== PUB.length) throw new Error("expected " + PUB.length + " public signals");
  return Object.fromEntries(PUB.map((k, i) => [k, BigInt(signals[i])]));
};

// Error output for scripts that hold an RPC URL or a key: URLs and long hex strings are masked on every path,
// including unhandled rejections, and a malformed key is refused before ethers can echo it.
const scrub = (s) => String(s).replace(/(https?|wss?):\/\/\S+/g, "<rpc>").replace(/0x[0-9a-fA-F]{60,}/g, "<hex>")
  .replace(/\b[0-9a-fA-F]{64}\b/g, "<hex>");
function guardSecrets() {
  const fail = (e) => { console.error(scrub(e && e.message ? e.message : e)); process.exit(1); };
  process.on("unhandledRejection", fail);
  process.on("uncaughtException", fail);
  return fail;
}
function privateKey(env) {
  const k = String(env.PRIVATE_KEY || "").trim().replace(/^["']|["']$/g, "");
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(k)) throw new Error("PRIVATE_KEY missing or malformed (value not shown)");
  return k;
}

module.exports = { scrub, guardSecrets, privateKey, P, mod, inv, randField, postHash, dayNumber, hasher, Tree, makeCredential, postInput,
  limitFor, benchWorkload, BENCH_DAY, DAY_1970, EPOCH_HOURS, dayOfEpoch, epochOfDay, yearsBefore, communityId, NO_AGE_GATE, MENU,
  policyFormHash, policyForEpoch, anchoredValue, epochStart, policyAnchorOf, POLICY_LEAD_S, acceptPolicyForm, rootAcceptable, auditRoots, IndexCounter, nullifierOf, checkPost, recoverSecret,
  art, PUB, pub, ROOT };
