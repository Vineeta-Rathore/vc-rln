// The circuit, client and verifier checks at depth 20: functional and negative circuit tests, the policy anchor,
// the index counter, the verifier's post checks. Writes data/tests_circuit.json.
//   node scripts/test_circuit.js
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const L = require("./lib");

const results = [];
function record(name, expected, observed, pass) {
  results.push({ name, expected, observed, pass });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}  (${observed})`);
}
async function prove(art, input) {
  return snarkjs.groth16.fullProve(input, art.wasm, art.zkey);
}
// Negative cases must fail at the constraint they target: template and line of the innermost failing assertion
// (the range checks fail inside circomlib's Num2Bits, whatever its line).
const AT = { root: ["VCRLN", 80], ageGate: ["VCRLN", 95], limit: ["VCRLN", 106], range: ["Num2Bits", null] };
async function failsAt(art, input) {
  try { await prove(art, input); return null; } catch (e) {
    const m = String(e.message || e).match(/Error in template (\w+?)_\d+ line: (\d+)/);
    return m ? { template: m[1], line: Number(m[2]) } : { template: "?", line: -1 };
  }
}
async function proveFails(art, input) { return (await failsAt(art, input)) !== null; }
async function negative(name, art, input, which) {
  const got = await failsAt(art, input), [tpl, line] = AT[which];
  const hit = got !== null && got.template === tpl && (line === null || got.line === line);
  record(name, `witness fails in ${tpl}${line ? " line " + line : ""} (${which})`, got === null ? "proof produced" : `fails in ${got.template} line ${got.line}`, hit);
}

(async () => {
  const H = await L.hasher();
  const art = L.art("vcrln_d20");
  const today = L.dayNumber("2026-10-26");
  const schema = H(BigInt(L.postHash("IC4 SocialAccountCredential v1")));
  const general = { community: L.postHash("community:general"), ageCutoff: (1 << 20) - 1,
    seniorityCutoff: today - 30, baseLimit: 1, verifiedBonus: 4, seniorityBonus: 5, mode: 0 };
  const adults = { ...general, community: L.postHash("community:18plus"), ageCutoff: L.dayNumber("2008-10-26"), mode: 1 };
  const other = { ...adults, community: L.postHash("community:other") };
  const epoch = L.epochOfDay(today);  // hour index of 2026-10-26 00:00 UTC (one-hour epochs)

  const tree = new L.Tree(H, 20);
  const mk = (b, t, v) => L.makeCredential(H, { secret: L.randField(), birthDate: L.dayNumber(b),
    accountCreated: L.dayNumber(t), verifiedHuman: v, schema, salt: L.randField() });
  const A = mk("1995-03-14", "2024-01-10", 1);   // verified, senior, adult: limit 1+4+5 = 10
  const B = mk("2000-06-01", "2026-10-20", 0);   // unverified, new, adult: limit 1
  const C = mk("2010-05-05", "2025-01-01", 1);   // verified, senior, minor
  const iA = tree.insert(A.leaf), iB = tree.insert(B.leaf), iC = tree.insert(C.leaf);
  for (let i = 0; i < 5; i++) tree.insert(L.randField());  // other members

  // T1 honest post verifies and the public signals carry the policy
  let r = await prove(art, L.postInput(tree, iA, A, general, epoch, "hello", 0));
  let ok = await snarkjs.groth16.verify(art.vkey, r.publicSignals, r.proof);
  const s1 = L.pub(r.publicSignals);
  record("T1 honest post verifies", "true", String(ok), ok && s1.root === tree.root() && s1.x === L.postHash("hello") && s1.pseudonym === 0n);

  // T2/T3 limits follow the hidden attributes
  record("T2 B message 0 accepted", "proof", "proof", !(await proveFails(art, L.postInput(tree, iB, B, general, epoch, "b0", 0))));
  await negative("T2 B message 1 rejected (j >= limit)", art, L.postInput(tree, iB, B, general, epoch, "b1", 1), "limit");
  record("T3 A message 9 accepted (limit 10)", "proof", "proof", !(await proveFails(art, L.postInput(tree, iA, A, general, epoch, "a9", 9))));
  await negative("T3 A message 10 rejected", art, L.postInput(tree, iA, A, general, epoch, "a10", 10), "limit");

  // T4 age gate
  await negative("T4 minor rejected in 18+ community", art, L.postInput(tree, iC, C, adults, epoch, "c", 0), "ageGate");
  record("T4 minor accepted in ungated community", "proof", "proof", !(await proveFails(art, L.postInput(tree, iC, C, general, epoch, "c", 0))));

  // T5 exceeding the limit (reusing a message index) reveals the secret
  const p1 = L.pub((await prove(art, L.postInput(tree, iA, A, general, epoch, "first post", 3))).publicSignals);
  const p2 = L.pub((await prove(art, L.postInput(tree, iA, A, general, epoch, "second post", 3))).publicSignals);
  const s = L.recoverSecret(p1.x, p1.y, p2.x, p2.y);
  record("T5 same index, same epoch: equal nullifiers", "equal", p1.nullifier === p2.nullifier ? "equal" : "different", p1.nullifier === p2.nullifier);
  record("T5 secret recovered and matches the leaf's identity commitment", "H(s) = C_id", H(s) === A.idCommitment ? "match" : "no match", s === A.secret && H(s) === A.idCommitment);

  // T6 unlinkability sanity: nullifiers differ across indices, epochs and communities
  const n = async (pol, e, j) => L.pub((await prove(art, L.postInput(tree, iA, A, pol, e, "t6", j))).publicSignals).nullifier;
  const nBase = p1.nullifier, nIdx = await n(general, epoch, 4), nEp = await n(general, epoch + 1, 3), nCom = await n(other, epoch, 3);
  record("T6 nullifiers differ across index, epoch, community", "all distinct", [nIdx, nEp, nCom].every((v) => v !== nBase) ? "all distinct" : "collision",
    new Set([nBase, nIdx, nEp, nCom]).size === 4);

  // T7 community verifier: a changed public signal fails the proof; a valid proof made under another policy, a
  // resent post and a second post with a used index are each told apart by the checks besides the proof
  const t = await prove(art, L.postInput(tree, iA, A, general, epoch, "tamper", 5));
  { const ps = t.publicSignals.slice(); ps[7] = (BigInt(ps[7]) + 1n).toString();
    const v = await snarkjs.groth16.verify(art.vkey, ps, t.proof);
    record("T7 changed x fails the proof", "false", String(v), v === false); }
  const ctx = { schema, policy: general, epoch, text: "tamper" }, seenN = new Map();
  const loose = await prove(art, L.postInput(tree, iA, A, { ...general, baseLimit: 60 }, epoch, "tamper", 5));
  const OK = { proofValid: true, rootAcceptable: true };  // the proofs below are valid and against the current root
  const lr = L.checkPost(L.pub(loose.publicSignals), ctx, new Map(), OK);
  record("T7 valid proof under a looser policy rejected", "public input baseLimit", lr.reason, lr.reason === "public input baseLimit");
  const first = L.checkPost(L.pub(t.publicSignals), ctx, seenN, OK), again = L.checkPost(L.pub(t.publicSignals), ctx, seenN, OK);
  record("T7 resent post dropped as replay, secret not revealed", "replay", again.reason, first.ok && again.reason === "replay" && again.secret === undefined);
  const t2 = await prove(art, L.postInput(tree, iA, A, general, epoch, "tamper 2", 5));
  const over = L.checkPost(L.pub(t2.publicSignals), { ...ctx, text: "tamper 2" }, seenN, OK);
  record("T7 second post with a used index reveals the secret", "over limit", over.reason, over.reason === "over limit" && over.secret === A.secret);

  // T8 a holder cannot claim a better tier than the one committed in its leaf
  const forged = { ...L.postInput(tree, iB, B, general, epoch, "forge", 2), verifiedHuman: 1 };
  await negative("T8 claiming verifiedHuman=1 with an unverified leaf fails", art, forged, "root");

  // T9 revocation: after the leaf is zeroed, no proof against the new root; but a member who kept the old path can
  // still make fresh proofs against the superseded root, so revocation takes effect only when that root leaves the
  // verifier's window
  const kept = L.postInput(tree, iB, B, general, epoch, "after revoke, old path", 0);
  tree.revoke(iB);
  await negative("T9 revoked member cannot prove against the new root", art, L.postInput(tree, iB, B, general, epoch, "after revoke", 0), "root");
  const fresh = await prove(art, kept);
  const stillValid = await snarkjs.groth16.verify(art.vkey, fresh.publicSignals, fresh.proof);
  record("T9 fresh proof after revocation against the superseded root verifies (window bounds it)", "true", String(stillValid), stillValid === true && L.pub(fresh.publicSignals).root !== tree.root());

  // T10 pseudonymous mode: stable inside one community, different across communities, 0 in anonymous mode
  const ps = async (pol, e) => L.pub((await prove(art, L.postInput(tree, iA, A, pol, e, "t10", 0))).publicSignals).pseudonym;
  const q1 = await ps(adults, epoch), q2 = await ps(adults, epoch + 7), q3 = await ps(other, epoch), q0 = await ps(general, epoch);
  record("T10 pseudonym stable across epochs in one community", "equal", q1 === q2 ? "equal" : "different", q1 === q2 && q1 !== 0n);
  record("T10 pseudonym differs across communities; 0 in anonymous mode", "distinct, 0", `${q1 !== q3}, ${q0}`, q1 !== q3 && q0 === 0n);

  // T11 policy anchoring. Clients read the anchored value from the community DID's events: exactly one valid value
  // counts, a revoked one is ignored, two valid ones or none stop the client, and so does a deactivated DID. The form
  // must name the DID it was read from, the issuer and schema of the member's credential, offsets from the client's
  // menu and limit coefficients in range; two clients that read the same events derive the same policy for an epoch.
  const DID_C = "did:ethr:opsepolia:0x00000000000000000000000000000000000000c1", ISSUER = "did:ethr:opsepolia:0x00000000000000000000000000000000000000a1";
  const form = { did: DID_C, issuer: ISSUER, schema: schema.toString(), ageYears: null, seniorityOffsetDays: 30, baseLimit: 1, verifiedBonus: 4, seniorityBonus: 5, mode: 0 };
  const hForm = L.policyFormHash(form), hOther = L.policyFormHash({ ...form, seniorityOffsetDays: 365 }), now = 1800000000;
  let evBlock = 100;  // events in log order: one block each, unless given
  const ev = (value, validTo, time = now - 100, block = evBlock++) => ({ name: "ic4/policy/v1", value, validTo, time, block, logIndex: 0 });
  const events = [ev(hOther, now + 9e6), ev(hOther, 0), ev(hForm, now + 9e6)];
  const clientA = L.anchoredValue(events.slice(), "ic4/policy/v1", now), clientB = L.anchoredValue(events.slice().reverse(), "ic4/policy/v1", now);
  const big = (o) => JSON.stringify(o, (k, v) => (typeof v === "bigint" ? v.toString() : v));
  const pa = L.policyForEpoch(form, epoch);
  const same = clientA === hForm && clientB === hForm;
  const credInfo = { issuer: ISSUER, schema: schema.toString() };
  const acc = L.acceptPolicyForm(form, clientA, DID_C, credInfo).ok;
  record("T11 two clients reading the anchor (one revoked, one valid value; events in any order) find the same form and accept it", "same, accepted",
    `${same ? "same" : "different"}, ${acc}`, same && acc);
  const err = (f) => { try { f(); return "no error"; } catch (e) { return e.message; } };
  const val = (f) => { try { return f(); } catch (e) { return e.message; } };  // the value, or the refusal
  const two = err(() => L.anchoredValue([ev(hForm, now + 9e6), ev(hOther, now + 9e6)], "ic4/policy/v1", now));
  const none = err(() => L.anchoredValue([ev(hForm, now - 1)], "ic4/policy/v1", now));
  const edge = val(() => L.anchoredValue([ev(hForm, now)], "ic4/policy/v1", now));  // validTo == at is valid, as in ethr-did-resolver
  const deact = err(() => L.anchoredValue([ev(hForm, now + 9e6), { kind: "owner", owner: "0x0000000000000000000000000000000000000000", time: now - 50, block: evBlock++, logIndex: 0 }], "ic4/policy/v1", now));
  const noTime = err(() => L.anchoredValue([{ ...ev(hForm, now + 9e6), time: "" }], "ic4/policy/v1", now));
  record("T11 two valid values, only an expired one, a deactivated DID or an event without a block time stop the client; validTo = t is valid",
    "several; none; deactivated; bad time; valid", `${two}; ${none}; ${deact}; ${noTime}; ${edge === hForm ? "valid" : edge}`,
    two === "several anchored values" && none === "no anchored value" && deact === "DID deactivated" && noTime === "bad event time" && edge === hForm);
  const tagged = L.acceptPolicyForm({ ...form, seniorityOffsetDays: 29 }, hForm, DID_C, credInfo);
  record("T11 a per-member policy that is not anchored is refused", "not anchored", tagged.reason, tagged.reason === "not anchored");
  const offForm = { ...form, seniorityOffsetDays: 29 }, off = L.acceptPolicyForm(offForm, L.policyFormHash(offForm), DID_C, credInfo);
  const wrapForm = { ...form, baseLimit: 300 }, wrap = L.acceptPolicyForm(wrapForm, L.policyFormHash(wrapForm), DID_C, credInfo);
  record("T11 an anchored form with an offset off the client's menu, or a limit coefficient above 255, is refused", "offset not on menu; limit field out of range",
    `${off.reason}; ${wrap.reason}`, off.reason === "offset not on menu" && wrap.reason === "limit field out of range");
  const foreign = L.acceptPolicyForm(form, hForm, "did:ethr:opsepolia:0x00000000000000000000000000000000000000ff", credInfo);
  record("T11 a form read from one DID but naming another is refused", "form names another DID", foreign.reason, foreign.reason === "form names another DID");
  const sigma = L.acceptPolicyForm(form, hForm, DID_C, { issuer: ISSUER, schema: "12345" });
  record("T11 a credential with a schema other than the anchored one is refused", "issuer or schema not the anchored one", sigma.reason,
    sigma.reason === "issuer or schema not the anchored one");
  const ap = await prove(art, L.postInput(tree, iA, A, pa, epoch, "anchored", 0));
  const apOk = await snarkjs.groth16.verify(art.vkey, ap.publicSignals, ap.proof);
  record("T11 a post under the anchored policy verifies", "true", String(apOk), apOk);

  // T12 client index counter. Each scenario uses its own state file, created at enrollment two epochs before.
  const tmpBase = path.join(require("os").tmpdir(), `ic4_counter_${process.pid}`);
  const tmps = [];
  const freshState = (name, device = 0, devices = 1, enrolled = epoch - 2) => {
    const f = `${tmpBase}_${name}.json`; tmps.push(f);
    for (const x of [f, f + ".lock", f + ".tmp", f + ".unreadable"]) if (fs.existsSync(x)) fs.unlinkSync(x);
    L.IndexCounter.init(f, enrolled, device, devices); return f;
  };
  const CC = pa.community;
  {  // restart and retry
    const f = freshState("restart");
    const c1 = new L.IndexCounter(f), j0 = c1.take(epoch, CC, 10, "p1"), j1 = c1.take(epoch, CC, 10, "p2");
    const c2 = new L.IndexCounter(f), j2 = c2.take(epoch, CC, 10, "p3"), jr = c2.take(epoch, CC, 10, "p1");
    record("T12 counter survives a restart; a retried post keeps its index", "0,1,2; retry 0", `${j0},${j1},${j2}; retry ${jr}`, j0 === 0 && j1 === 1 && j2 === 2 && jr === 0);
    const u1 = new L.IndexCounter(f), u2 = new L.IndexCounter(f);
    const k1 = u1.take(epoch + 1, CC, 10, "x1"), k2 = u2.take(epoch + 1, CC, 10, "x2"), k3 = u1.take(epoch + 1, CC, 10, "x3");
    record("T12 two client instances on one state file never share an index", "0,1,2", `${k1},${k2},${k3}`, k1 === 0 && k2 === 1 && k3 === 2);
    fs.writeFileSync(f + ".lock", "");  // another client holds the lock
    const locked = err(() => new L.IndexCounter(f).take(epoch + 1, CC, 10, "x4"));
    fs.unlinkSync(f + ".lock");
    record("T12 a client that finds the state locked by another client does not post", "counter is locked by another client", locked,
      locked === "counter is locked by another client");
  }
  {  // devices
    const d0 = new L.IndexCounter(freshState("d0", 0, 2), 0, 2), d1 = new L.IndexCounter(freshState("d1", 1, 2), 1, 2), used = [];
    for (let k = 0; k < 5; k++) used.push(d0.take(epoch, CC, 10, "a" + k), d1.take(epoch, CC, 10, "b" + k));
    const stopped = /limit reached/.test(err(() => d0.take(epoch, CC, 10, "a5")));
    const badDev = err(() => new L.IndexCounter(tmpBase + "_x.json", 2, 2));
    const changed = err(() => new L.IndexCounter(`${tmpBase}_d0.json`, 0, 3).take(epoch, CC, 10, "c"));
    record("T12 two devices split the indices, never share one and stop at the limit; a bad device number or a changed device count stops the client",
      "10 distinct, stopped; refusals", `${new Set(used).size} distinct, ${stopped ? "stopped" : "not stopped"}; ${badDev}; ${changed}`,
      new Set(used).size === 10 && stopped && badDev === "bad device number" && changed === "device count changed within the epoch");
  }
  {  // a fresh state (reinstall, new device) cannot post in the epoch it was created in or the next
    const f = freshState("reinstall", 0, 1, epoch);
    const same = err(() => new L.IndexCounter(f).take(epoch, CC, 10, "r1")), next = err(() => new L.IndexCounter(f).take(epoch + 1, CC, 10, "r2"));
    const after = val(() => new L.IndexCounter(f).take(epoch + 2, CC, 10, "r3"));
    record("T12 a state created in this epoch (reinstall, new device) posts only from the epoch after next", "refused; refused; then 0",
      `${same}; ${next}; then ${after}`, /new or was lost/.test(same) && /new or was lost/.test(next) && after === 0);
  }
  {  // lost state: missing after enrollment, deleted twice, unreadable, malformed
    const f = freshState("lost");
    new L.IndexCounter(f).take(epoch, CC, 10, "z1");
    fs.unlinkSync(f);
    const missing = err(() => new L.IndexCounter(f).take(epoch, CC, 10, "z2"));
    fs.unlinkSync(f);
    const reinit = val(() => { L.IndexCounter.init(f, epoch); return new L.IndexCounter(f).take(epoch, CC, 10, "z3"); });
    const missingNext = val(() => new L.IndexCounter(f).take(epoch + 2, CC, 10, "z4"));
    record("T12 a state deleted after enrollment, even twice and re-initialised, stops posting for this epoch and the next; fresh indices after",
      "missing; refused; 0", `${missing}; ${reinit}; ${missingNext}`, /missing/.test(missing) && /new or was lost/.test(reinit) && missingNext === 0);
    // the loss is noticed while the clock is one epoch behind: the epoch of the used index is still refused
    const h = freshState("behind");
    new L.IndexCounter(h).take(epoch, CC, 10, "w1");
    fs.unlinkSync(h);
    const behind = err(() => new L.IndexCounter(h).take(epoch - 1, CC, 10, "w2")), atE = err(() => new L.IndexCounter(h).take(epoch, CC, 10, "w3"));
    record("T12 a loss noticed with the clock one epoch behind still refuses the epoch whose index was used", "missing; refused",
      `${behind}; ${atE}`, /missing/.test(behind) && /new or was lost/.test(atE));
    const bad = [];
    for (const content of ["{ truncated", '{"slots":[]}', '{"slots":{"1:2":{"next":"x","devices":1,"posts":{}}}}', '{"slots":{},"lostAt":"soon"}', '{"slots":{}}']) {
      const g = freshState("bad" + bad.length);
      fs.writeFileSync(g, content);
      bad.push(/unreadable/.test(err(() => new L.IndexCounter(g).take(epoch, CC, 10, "y"))) && /new or was lost/.test(err(() => new L.IndexCounter(g).take(epoch, CC, 10, "y2"))));
    }
    record("T12 truncated or malformed states (array slots, non-integer index, non-integer epoch, missing guard fields) count as lost",
      "5 refused", `${bad.filter(Boolean).length} refused`, bad.every(Boolean));
  }
  {  // clock jumps and aliases
    const f = freshState("clock");
    const a = new L.IndexCounter(f).take(epoch, CC, 10, "c1");
    const ahead = new L.IndexCounter(f).take(epoch + 2, CC, 10, "c2");
    const back = err(() => new L.IndexCounter(f).take(epoch, CC, 10, "c3"));
    record("T12 after a post in a later epoch (clock set forward) an earlier epoch is refused, so a used slot is never pruned and reused",
      "0, 0; refused", `${a}, ${ahead}; ${back}`, a === 0 && ahead === 0 && /earlier than one already used/.test(back));
    const g = freshState("alias");
    const dec = new L.IndexCounter(g).take(epoch, CC, 10, "h1"), hex = new L.IndexCounter(g).take(epoch, "0x" + BigInt(CC).toString(16), 10, "h2");
    const wrapC = err(() => new L.IndexCounter(g).take(epoch, BigInt(CC) + L.P, 10, "h3")), badEpoch = err(() => new L.IndexCounter(g).take(String(epoch), CC, 10, "h4"));
    record("T12 one community written in decimal or hex has one slot; a community outside the field or a non-integer epoch is refused",
      "0, 1; refused; refused", `${dec}, ${hex}; ${wrapC}; ${badEpoch}`, dec === 0 && hex === 1 && /not a field element/.test(wrapC) && badEpoch === "bad epoch");
  }
  {  // a state restored from an older copy: the member's own nullifiers in the community's table catch the reuse
    const f = freshState("rollback");
    const t0 = new L.IndexCounter(f).take(epoch, CC, 10, "b1"), copy = fs.readFileSync(f, "utf8");
    const t1 = new L.IndexCounter(f).take(epoch, CC, 10, "b2");
    fs.writeFileSync(f, copy);  // restored backup
    const table = new Set([t0, t1]);  // indices whose nullifiers the community has already seen from this member
    const naive = new L.IndexCounter(f).take(epoch, CC, 10, "b3");
    fs.writeFileSync(f, copy);
    const checked = new L.IndexCounter(f).take(epoch, CC, 10, "b4", (j) => table.has(j));
    record("T12 after a state is rolled back, the nullifier check skips indices already used", "without check 1 (reuse); with check 2",
      `without check ${naive}; with check ${checked}`, naive === 1 && checked === 2);
    const own = L.nullifierOf(H, A.secret, epoch, pa.community, 0), proved = L.pub(ap.publicSignals).nullifier;
    record("T12 the client computes its own nullifier for an index exactly as the circuit does", "equal", own === proved ? "equal" : "different", own === proved);
  }
  for (const f of tmps) for (const x of [f, f + ".lock", f + ".tmp", f + ".unreadable"]) if (fs.existsSync(x)) fs.unlinkSync(x);

  // T13 a post made for one community is refused by the verifier of another
  const cross = L.checkPost(L.pub(t.publicSignals), { schema, policy: other, epoch, text: "tamper" }, new Map(), OK);
  record("T13 post for one community refused by another community's verifier", "public input community", cross.reason, cross.reason === "public input community");

  // T14 range checks: values that wrap around the field or exceed the bit widths fail inside Num2Bits
  const base = L.postInput(tree, iA, A, general, epoch, "range", 0);
  await negative("T14 message index 2^16 fails the range check", art, { ...base, messageId: 65536 }, "range");
  await negative("T14 message index p-1 (a wrapped -1) fails the range check", art, { ...base, messageId: (L.P - 1n).toString() }, "range");
  // an attribute is part of the leaf, so a changed one fails the root check first; to reach the range check the
  // out-of-range date must be in a leaf, as an issuer's mistake would put it there
  const W20 = L.makeCredential(H, { secret: L.randField(), birthDate: 1 << 20, accountCreated: L.dayNumber("2024-01-10"),
    verifiedHuman: 1, schema, salt: L.randField() });
  const iW = tree.insert(W20.leaf);
  await negative("T14 birth date 2^20 in an issued leaf fails the range check", art, L.postInput(tree, iW, W20, general, epoch, "range", 0), "range");
  await negative("T14 age cutoff p-1 fails the range check", art, { ...base, ageCutoff: (L.P - 1n).toString() }, "range");

  // T15 a public signal outside the field (nullifier + p, the same field element) is rejected by the verifier
  { const ps = t.publicSignals.slice(); ps[1] = (BigInt(ps[1]) + L.P).toString();
    const v = await snarkjs.groth16.verify(art.vkey, ps, t.proof);
    record("T15 non-canonical nullifier (+p) rejected by verification", "false", String(v), v === false); }

  // T16 malformed input is rejected, not thrown; a post whose proof failed never enters the nullifier table, so a
  // forged share sent first cannot make the member's genuine post look like a second one
  let thrown = false;
  try { L.pub(t.publicSignals.slice(0, 13)); } catch (e) { thrown = true; }
  const mal = L.checkPost(L.pub(t.publicSignals), { schema, policy: { community: general.community }, epoch, text: "tamper" }, new Map(), OK);
  record("T16 wrong signal count and incomplete policy are rejected", "rejected, malformed", `${thrown ? "rejected" : "accepted"}, ${mal.reason}`, thrown && mal.reason === "malformed");
  const gate = new Map(), forged2 = L.pub(t2.publicSignals);
  const fr = L.checkPost(forged2, { ...ctx, text: "tamper 2" }, gate, { proofValid: false, rootAcceptable: true });
  const genuine = L.checkPost(L.pub(t.publicSignals), ctx, gate, OK);
  record("T16 a forged share with an invalid proof does not block the genuine post", "proof; then ok", `${fr.reason}; then ${genuine.ok ? "ok" : genuine.reason}`,
    fr.reason === "proof" && gate.size === 1 && genuine.ok);

  // T17 dates count from 1900, so a member born in 1950 can post in an ungated and in an 18+ community
  const OLD = L.makeCredential(H, { secret: L.randField(), birthDate: L.dayNumber("1950-06-01"), accountCreated: L.dayNumber("2020-01-01"),
    verifiedHuman: 1, schema, salt: L.randField() });
  const iOld = tree.insert(OLD.leaf);
  const o1 = await prove(art, L.postInput(tree, iOld, OLD, general, epoch, "born 1950", 0));
  const o2 = await prove(art, L.postInput(tree, iOld, OLD, adults, epoch, "born 1950, 18+", 0));
  const oOk = (await snarkjs.groth16.verify(art.vkey, o1.publicSignals, o1.proof)) && (await snarkjs.groth16.verify(art.vkey, o2.publicSignals, o2.proof));
  record("T17 a member born in 1950 posts in an ungated and in an 18+ community", "true", String(oOk), oOk);

  // T18 one policy per epoch: the form of epoch e is the one anchored POLICY_LEAD_S before e starts. A form anchored
  // inside that lead time, or during e, governs e + 1, so client and verifier use one form for all of e; a post proved
  // in e under the later form is refused by e's verifier, which derives the policy itself from the events.
  {
    const t0 = L.epochStart(epoch), tight = { ...form, verifiedBonus: 0 }, hTight = L.policyFormHash(tight), forms = { [hForm]: form, [hTight]: tight };
    const evs = [ev(hForm, t0 + 9e6, t0 - 3600), ev(hForm, 0, t0 - 300), ev(hTight, t0 + 9e6, t0 - 300)];
    const inE = L.policyAnchorOf(evs, "ic4/policy/v1", epoch, t0), inNext = L.policyAnchorOf(evs, "ic4/policy/v1", epoch + 1, t0 + 3600);
    const early = err(() => L.policyAnchorOf(evs, "ic4/policy/v1", epoch, t0 - L.POLICY_LEAD_S));  // a view at the policy time itself may miss a later block with the same time
    record("T18 a form anchored within the lead time before epoch e governs e + 1, not e; a view that has not reached the policy time is refused",
      "old form; new form; refused", `${inE === hForm ? "old form" : "other"}; ${inNext === hTight ? "new form" : "other"}; ${early}`,
      inE === hForm && inNext === hTight && early === "the chain view has not passed the policy time");
    const mid = await prove(art, L.postInput(tree, iA, A, L.policyForEpoch(tight, epoch), epoch, "mid-epoch form", 0));
    const midOk = await snarkjs.groth16.verify(art.vkey, mid.publicSignals, mid.proof);
    const r = L.checkPost(L.pub(mid.publicSignals), { schema, policy: L.policyForEpoch(forms[inE], epoch), epoch, text: "mid-epoch form" }, new Map(),
      { proofValid: midOk, rootAcceptable: true });
    record("T18 a post proved in epoch e under the later form is refused by e's verifier", "public input verifiedBonus", r.reason,
      r.reason === "public input verifiedBonus");
  }

  const passed = results.filter((x) => x.pass).length;
  console.log(`\n${passed}/${results.length} checks passed`);
  fs.writeFileSync(path.join(L.ROOT, "data", "tests_circuit.json"), JSON.stringify({ circuit: "vcrln_d20", date: new Date().toISOString(), passed, total: results.length, results }, null, 1));
  process.exit(passed === results.length ? 0 : 1);
})().catch((e) => { console.error("test run aborted:", e); process.exit(1); });
