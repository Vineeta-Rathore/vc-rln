// End-to-end DID + VC + ZKP run on OP Sepolia, against the registry deployed by the last complete testnet run:
//  1. an auditor rebuilds the issuer's tree from the chain log alone and compares it with the published root;
//  2. the issuer publishes its Ed25519 key in its did:ethr document (ERC-1056 attribute);
//  3. the issuer enrolls a new member (leaf on-chain) and issues a W3C VC 2.0 (eddsa-jcs-2022) that carries the
//     attributes, salt, identity commitment, leaf and leaf index;
//  4. the holder resolves the issuer DID, verifies the VC, recomputes the leaf and checks the root on-chain;
//  5. the community anchors its policy form; in the first epoch that form governs, the member reads it from a safe block;
//  6. the member posts once and the verifier, which audits the issuer's log, accepts it; it drops the post when resent,
//     refuses a looser policy and recovers the secret from a reused index; a rolled-back counter skips the used index.
//   node scripts/vc_demo.js        (writes data/vc_demo.json; needs PRIVATE_KEY in .env and an earlier
//                                   NET=opSepolia scripts/testnet.js run with the same key)
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { ethers } = require("ethers");
const { Resolver } = require("did-resolver");
const { getResolver } = require("ethr-did-resolver");
const snarkjs = require("snarkjs");
const L = require("./lib");
const fail = L.guardSecrets();

const ENV_FILE = process.env.ENV_FILE || path.join(L.ROOT, ".env");  // testnet-only key and RPC URLs; never printed
const ENV = { ...(require("dotenv").config({ path: ENV_FILE, processEnv: {} }).parsed || {}), ...process.env };
const RPC = ENV.OP_RPC || "https://sepolia.optimism.io", CHAIN = 11155420;
const now = () => Number(process.hrtime.bigint()) / 1e6;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const art = (n, c = n) => JSON.parse(fs.readFileSync(path.join(L.ROOT, "artifacts", "contracts", n + ".sol", c + ".json"), "utf8"));

// RFC 8785 canonical JSON for the value types used here (strings, integers, booleans, arrays, objects)
const jcs = (v) => Array.isArray(v) ? "[" + v.map(jcs).join(",") + "]"
  : v && typeof v === "object" ? "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + jcs(v[k])).join(",") + "}"
  : JSON.stringify(v);
const sha256 = (s) => crypto.createHash("sha256").update(s).digest();
const multikey = (raw) => "z" + ethers.encodeBase58(Buffer.concat([Buffer.from([0xed, 0x01]), raw]));

function signVC(doc, vmId, privateKey, created) {  // eddsa-jcs-2022 (W3C Data Integrity EdDSA)
  const proofConfig = { "@context": doc["@context"], type: "DataIntegrityProof", cryptosuite: "eddsa-jcs-2022", created,
    verificationMethod: vmId, proofPurpose: "assertionMethod" };
  const data = Buffer.concat([sha256(jcs(proofConfig)), sha256(jcs(doc))]);
  const sig = crypto.sign(null, data, privateKey);
  return { ...doc, proof: { ...proofConfig, proofValue: "z" + ethers.encodeBase58(sig) } };
}
// `didDoc` is the resolved document of vc.issuer; the key must belong to that DID and be listed under
// assertionMethod (vc-di-eddsa, verify proof). Malformed input returns false instead of throwing.
function verifyVC(vc, didDoc) {
  try {
    const { proof, ...doc } = vc;
    if (!proof || proof.type !== "DataIntegrityProof" || proof.cryptosuite !== "eddsa-jcs-2022" || proof.proofPurpose !== "assertionMethod") return false;
    if (!Array.isArray(doc.type) || !doc.type.includes("VerifiableCredential")) return false;
    // VC 2.0: the base context first; terms without a published context need the undefined-terms context last
    const ctx = doc["@context"];
    if (!Array.isArray(ctx) || ctx[0] !== "https://www.w3.org/ns/credentials/v2" || ctx.at(-1) !== "https://www.w3.org/ns/credentials/undefined-terms/v2") return false;
    for (const d of [doc.validFrom, doc.validUntil]) if (d !== undefined && Number.isNaN(Date.parse(d))) return false;
    if (doc.validFrom && Date.parse(doc.validFrom) > Date.now()) return false;
    if (doc.validUntil && Date.parse(doc.validUntil) < Date.now()) return false;
    const vmId = proof.verificationMethod;
    if (!didDoc || didDoc.id !== doc.issuer || typeof vmId !== "string" || !vmId.startsWith(doc.issuer + "#")) return false;
    if (!(didDoc.assertionMethod || []).some((m) => (typeof m === "string" ? m : m.id) === vmId)) return false;
    const vm = (didDoc.verificationMethod || []).find((m) => m.id === vmId);
    if (!vm || (vm.controller && vm.controller !== doc.issuer)) return false;
    if (typeof vm.publicKeyMultibase !== "string" || vm.publicKeyMultibase[0] !== "z") return false;
    const { proofValue, ...proofConfig } = proof;  // proof options carry the document @context (vc-di-eddsa, jcs)
    if (JSON.stringify(proofConfig["@context"]) !== JSON.stringify(doc["@context"])) return false;
    if (typeof proofValue !== "string" || proofValue[0] !== "z") return false;
    const keyBytes = ethers.getBytes(ethers.toBeHex(ethers.decodeBase58(vm.publicKeyMultibase.slice(1))));
    if (keyBytes.length !== 34 || keyBytes[0] !== 0xed || keyBytes[1] !== 0x01) return false;  // multicodec ed25519-pub
    const sigInt = ethers.decodeBase58(proofValue.slice(1));
    if (sigInt >= 1n << 512n) return false;
    const data = Buffer.concat([sha256(jcs(proofConfig)), sha256(jcs(doc))]);
    const key = crypto.createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(keyBytes.subarray(2)).toString("base64url") }, format: "jwk" });
    return crypto.verify(null, data, key, Buffer.from(ethers.getBytes(ethers.toBeHex(sigInt, 64))));
  } catch (e) {
    return false;
  }
}

(async () => {
  const out = { network: "opSepolia", ts: new Date().toISOString(), steps: {} };
  const recs = fs.readFileSync(path.join(L.ROOT, "data", "testnet.jsonl"), "utf8").trim().split("\n").map(JSON.parse);
  const run = recs.filter((r) => r.net === "opSepolia" && r.run).map((r) => r.run).pop();
  const R = recs.filter((r) => r.run === run);
  const didAddr = R.find((r) => r.op === "deploy:EthereumDIDRegistry").contract;
  const regRec = R.find((r) => r.op === "deploy:IssuerRootRegistry");
  out.run = run; out.erc1056 = didAddr; out.registry = regRec.contract;

  const provider = new ethers.JsonRpcProvider(RPC, CHAIN, { staticNetwork: true });
  const wallet = new ethers.NonceManager(new ethers.Wallet(L.privateKey(ENV), provider));
  const me = await wallet.getAddress();
  const did = new ethers.Contract(didAddr, art("EthereumDIDRegistry").abi, wallet);
  const reg = new ethers.Contract(regRec.contract, art("IssuerRootRegistry").abi, wallet);
  const H = await L.hasher();
  const issuerDid = `did:ethr:opsepolia:${me.toLowerCase()}`;

  const blockTimes = {};
  const timeOf = async (b) => (blockTimes[b] ??= (await provider.getBlock(b)).timestamp);
  const must = (ok, what) => { if (ok !== true) throw new Error("check failed: " + what); };

  // 1. rebuild the issuer tree from the event log and compare with the published root
  let t = now();
  const head0 = await provider.getBlockNumber();
  const logs = [];
  for (let from = regRec.block; from <= head0; from += 2000) {
    const to = Math.min(head0, from + 1999);
    logs.push(...await reg.queryFilter(reg.filters.LeavesAdded(me), from, to), ...await reg.queryFilter(reg.filters.LeavesRevoked(me), from, to));
  }
  logs.sort((a, b) => a.blockNumber - b.blockNumber || a.index - b.index);
  const tree = new L.Tree(H, 20);
  for (const ev of logs) {
    if (ev.fragment.name === "LeavesAdded") ev.args.leaves.forEach((l) => tree.insert(l));
    else ev.args.indices.forEach((i) => tree.revoke(Number(i)));
  }
  const onchain = await reg.currentRoot(me);
  out.steps.rebuild = { events: logs.length, leaves: tree.leaves.length, rootMatches: tree.root() === onchain, ms: now() - t };
  must(out.steps.rebuild.rootMatches, "rebuilt tree matches the published root");
  console.log("rebuild:", out.steps.rebuild);

  // 2. issuer key in the DID document
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
  const rawPub = Buffer.from(publicKey.export({ format: "jwk" }).x, "base64url");
  t = now();
  const tx1 = await did.setAttribute(me, ethers.encodeBytes32String("did/pub/Ed25519/veriKey/base58"), rawPub, 86400 * 365);
  const rc1 = await tx1.wait();
  out.steps.setKey = { txHash: rc1.hash, gasUsed: Number(rc1.gasUsed), ms: now() - t };
  const resolver = new Resolver(getResolver({ networks: [{ name: "opsepolia", chainId: CHAIN, rpcUrl: RPC, registry: didAddr }] }));
  let doc, vm;
  for (let k = 0; k < 20 && !vm; k++) {  // wait until the resolver's RPC view includes the attribute
    doc = (await resolver.resolve(issuerDid)).didDocument;
    vm = doc && doc.verificationMethod.find((m) => m.publicKeyMultibase === multikey(rawPub));
    if (!vm) await sleep(1000);
  }
  if (!vm) throw new Error("issuer key not found in the resolved DID document");

  // 3. enrollment and VC issuance
  const today = L.dayNumber("2026-10-26");
  const schema = H(L.postHash("IC4 SocialAccountCredential v1"));
  const secret = L.randField();  // generated by the holder; only C_id goes to the issuer
  const cred = L.makeCredential(H, { secret, birthDate: L.dayNumber("1998-07-21"), accountCreated: L.dayNumber("2023-05-02"),
    verifiedHuman: 1, schema, salt: L.randField() });
  const index = tree.insert(cred.leaf);
  t = now();
  const rc2 = await (await reg.addLeaves(me, [cred.leaf], tree.root())).wait();
  out.steps.enrol = { txHash: rc2.hash, gasUsed: Number(rc2.gasUsed), leafIndex: index, ms: now() - t };
  // the member's counter is created at enrollment; it posts from the epoch after next
  const counterFile = path.join(require("os").tmpdir(), `ic4_member_${process.pid}.json`);
  const EPOCH_S = L.epochStart(1), enrolEpoch = Math.floor((await timeOf(rc2.blockNumber)) / EPOCH_S);
  const counter = L.IndexCounter.init(counterFile, enrolEpoch);
  t = now();
  const vc = signVC({
    // the application terms are not defined by a published context, so VC 2.0 (section 5.2) requires the
    // undefined-terms context as the last value
    "@context": ["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/undefined-terms/v2"],
    type: ["VerifiableCredential", "SocialAccountCredential"],
    issuer: issuerDid,
    validFrom: "2026-10-26T00:00:00Z",
    credentialSubject: { identityCommitment: cred.idCommitment.toString(), birthDate: "1998-07-21", accountCreated: "2023-05-02",
      verifiedHuman: true, salt: cred.salt.toString(), schema: schema.toString(), leaf: cred.leaf.toString() },
    credentialStatus: { id: `eip155:${CHAIN}:${regRec.contract}#${me}/${index}`, type: "IssuerRootRegistryLeaf", leafIndex: index },
  }, vm.id, privateKey, "2026-10-26T00:00:00Z");
  out.steps.issue = { ms: now() - t, vcBytes: Buffer.byteLength(JSON.stringify(vc)) };
  out.vc = vc;

  // 4. holder checks: resolve the issuer DID, verify the proof, recompute the leaf, check the root on-chain
  t = now();
  const holderDoc = (await resolver.resolve(vc.issuer)).didDocument;
  const tRes = now() - t;
  const sigOk = verifyVC(vc, holderDoc);
  const cs = vc.credentialSubject;
  const leaf = H(BigInt(cs.schema), H(secret), L.dayNumber(cs.birthDate), L.dayNumber(cs.accountCreated), cs.verifiedHuman ? 1 : 0, BigInt(cs.salt));
  const rootOk = (await reg.currentRoot(me)) === tree.root();  // the member uses the issuer's current on-chain root
  out.steps.holderCheck = { resolveMs: tRes, totalMs: now() - t, signatureValid: sigOk, leafMatches: leaf === BigInt(cs.leaf), rootIsCurrent: rootOk };
  const tampered = { ...vc, credentialSubject: { ...cs, verifiedHuman: false } };
  out.steps.holderCheck.tamperedRejected = !verifyVC(tampered, holderDoc);
  // a key that is in the document but not under assertionMethod (e.g. key agreement only) must not verify
  out.steps.holderCheck.nonAssertionKeyRejected = !verifyVC(vc, { ...holderDoc, assertionMethod: [] });
  // a document of another DID that lists the same key does not make the credential valid
  out.steps.holderCheck.foreignDocumentRejected = !verifyVC(vc, { ...holderDoc, id: "did:ethr:opsepolia:0x000000000000000000000000000000000000dead" });
  console.log("holder check:", out.steps.holderCheck);
  for (const [k, v] of Object.entries(out.steps.holderCheck)) if (typeof v === "boolean") must(v, "holder " + k);

  // 5. the community anchors the hash of its policy form as an ERC-1056 attribute of its DID. The form names the
  //    issuer and the schema it accepts; cutoffs are an age in years and a seniority offset in days. A member reads
  //    the identity's whole ERC-1056 history (changed() and the previousChange chain, as resolvers do) and accepts
  //    only if exactly one value of the attribute is valid. Here the platform runs the community, so the community DID
  //    is the issuer's own DID; earlier values of the attribute are revoked before the new one is set.
  const communityDid = `did:ethr:opsepolia:${me.toLowerCase()}`;
  const form = { did: communityDid, issuer: issuerDid, schema: schema.toString(), ageYears: 18, seniorityOffsetDays: 30,
    baseLimit: 1, verifiedBonus: 4, seniorityBonus: 5, mode: 0 };
  const POLICY = ethers.encodeBytes32String("ic4/policy/v1");
  const history = async (blockTag) => {  // the identity's ERC-1056 events (attributes and owner changes) up to blockTag, with block, log index and time
    const evs = [];
    let block = Number(await did.changed(me, { blockTag }));
    while (block > 0) {
      const logs = await provider.getLogs({ address: didAddr, fromBlock: block, toBlock: block, topics: [null, ethers.zeroPadValue(me, 32)] });
      const time = await timeOf(block);
      const parsed = logs.map((l) => ({ l, e: did.interface.parseLog(l) })).filter((x) => x.e);
      for (const { l, e } of parsed) {
        if (e.name === "DIDAttributeChanged") evs.push({ name: e.args[1], value: e.args[2], validTo: Number(e.args[3]), time, block, logIndex: l.index });
        else if (e.name === "DIDOwnerChanged") evs.push({ kind: "owner", owner: e.args[1], time, block, logIndex: l.index });
      }
      const prev = parsed.map(({ e }) => Number(e.args.previousChange)).filter((b) => b < block);
      block = prev.length ? Math.max(...prev) : 0;
    }
    return evs;
  };
  const nowS = () => Math.floor(Date.now() / 1000);
  t = now();
  const before = await history("latest");
  const lastOf = (v) => before.filter((e) => e.name === POLICY && e.value === v).sort((a, b) => a.block - b.block || a.logIndex - b.logIndex).pop();
  const stale = [...new Set(before.filter((e) => e.name === POLICY).map((e) => e.value))].filter((v) => lastOf(v).validTo >= nowS());
  out.steps.anchorPolicy = { revokedEarlier: stale.length };
  for (const v of stale) await (await did.revokeAttribute(me, POLICY, v, { gasLimit: 200000n })).wait();
  const rc3 = await (await did.setAttribute(me, POLICY, L.policyFormHash(form), 86400 * 365, { gasLimit: 200000n })).wait();
  Object.assign(out.steps.anchorPolicy, { txHash: rc3.hash, gasUsed: Number(rc3.gasUsed), ms: now() - t });
  // The form governs the first epoch whose policy time (POLICY_LEAD_S before its start) is not before the anchor's
  // block. Members and the verifier read it from a safe block that has reached that time; the epoch is taken from
  // the chain head and checked against the local clock.
  const anchorTime = await timeOf(rc3.blockNumber);
  // (and a counter created at enrollment posts from the epoch after next)
  const epoch = Math.max(Math.ceil((anchorTime + L.POLICY_LEAD_S) / EPOCH_S), enrolEpoch + 2);
  const headTime = async () => (await provider.getBlock("latest")).timestamp;
  out.steps.anchorPolicy.waitedS = Math.max(0, L.epochStart(epoch) + 5 - nowS());
  while ((await headTime()) < L.epochStart(epoch) + 5) await sleep(15000);
  let safe = await provider.getBlock("safe");
  while (safe.timestamp < L.epochStart(epoch) - L.POLICY_LEAD_S) { await sleep(15000); safe = await provider.getBlock("safe"); }
  t = now();
  const events = await history(safe.number);
  const anchored = L.policyAnchorOf(events, POLICY, epoch, safe.timestamp);
  out.steps.anchorPolicy.readMs = now() - t;
  out.steps.anchorPolicy.historyEvents = events.length;
  out.steps.anchorPolicy.epochAfterAnchor = epoch - Math.floor(anchorTime / EPOCH_S);
  const credInfo = { issuer: issuerDid, schema: schema.toString() };
  out.steps.anchorPolicy.memberAccepts = L.acceptPolicyForm(form, anchored, communityDid, credInfo).ok;
  out.steps.anchorPolicy.perMemberPolicyRefused = L.acceptPolicyForm({ ...form, seniorityOffsetDays: 29 }, anchored, communityDid, credInfo).reason === "not anchored";
  console.log("policy anchor:", out.steps.anchorPolicy);
  must(out.steps.anchorPolicy.memberAccepts, "member accepts the anchored form");
  must(out.steps.anchorPolicy.perMemberPolicyRefused, "per-member form refused");

  // 6. first post: the policy from the anchored form, the index from the member's persistent counter after checking
  //    its own nullifier against the community's table, the proof against the issuer's current on-chain root
  const head = await headTime();
  must(Math.floor(head / EPOCH_S) === epoch, "chain head in the post's epoch");
  must(Math.abs(head - nowS()) < 300, "local clock within 5 min of the chain");
  const pol = L.policyForEpoch(form, epoch);
  const seen = new Map();  // the community's nullifier table for this epoch
  const isUsed = (k) => seen.has(L.nullifierOf(H, secret, epoch, pol.community, k));
  const j = counter.take(epoch, pol.community, L.limitFor(cred, pol), "first post", isUsed);
  const current = await reg.currentRoot(me);
  out.steps.post = { rootIsCurrent: tree.root() === current, index: j, retrySameIndex: counter.take(epoch, pol.community, L.limitFor(cred, pol), "first post", isUsed) === j };
  const input = L.postInput(tree, index, cred, pol, epoch, "first post", j);
  t = now();
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, L.art("vcrln_d20").wasm, L.art("vcrln_d20").zkey);
  out.steps.post.proveMs = now() - t;
  // The community verifier derives the policy itself from a safe block and audits the issuer's log: a root counts
  // only where the events derive it, within W = 1 h, and until g = 5 min after the first revocation that follows it.
  t = now();
  const vsafe = await provider.getBlock("safe");
  must(L.policyAnchorOf(await history(vsafe.number), POLICY, epoch, vsafe.timestamp) === L.policyFormHash(form), "verifier reads the same form");
  const vpol = L.policyForEpoch(form, epoch);
  const regLogs = logs.slice();
  for (let from = head0 + 1, top = await provider.getBlockNumber(); from <= top; from += 2000) {
    const to = Math.min(top, from + 1999);
    regLogs.push(...await reg.queryFilter(reg.filters.LeavesAdded(me), from, to), ...await reg.queryFilter(reg.filters.LeavesRevoked(me), from, to));
  }
  const auditEvents = [];
  for (const ev of regLogs) auditEvents.push({ kind: ev.fragment.name === "LeavesAdded" ? "added" : "revoked", block: ev.blockNumber, logIndex: ev.index,
    time: await timeOf(ev.blockNumber), leaves: ev.args.leaves ?? [], indices: ev.args.indices ?? [], root: ev.args.root });
  const audit = L.auditRoots(H, 20, auditEvents);
  out.steps.post.verifierSetupMs = now() - t;
  out.steps.post.auditedEvents = auditEvents.length;
  out.steps.post.auditMismatched = audit.mismatched.length;
  must(audit.mismatched.length === 0, "every published root is derived by the log");
  const verifyPost = async (signals, prf, text, seenTable = new Map()) => {
    const ok = await snarkjs.groth16.verify(L.art("vcrln_d20").vkey, signals, prf);
    const p = L.pub(signals);
    const rootOk = L.rootAcceptable({ inWindow: await reg.isAcceptable(me, p.root, 3600), published: audit.published.get(p.root.toString()),
      revocations: audit.revocations, now: await headTime(), g: 300 });
    return L.checkPost(p, { schema: form.schema, policy: vpol, epoch, text }, seenTable, { proofValid: ok, rootAcceptable: rootOk });
  };
  t = now();
  const first = await verifyPost(publicSignals, proof, "first post", seen);
  out.steps.post.verifierTotalMs = now() - t;
  out.steps.post.accepted = first.ok;
  out.steps.post.replayRejected = (await verifyPost(publicSignals, proof, "first post", seen)).reason === "replay";
  {  // a state rolled back to before the post: the nullifier check skips the used index
    const st = JSON.parse(fs.readFileSync(counterFile, "utf8"));
    for (const slot of Object.values(st.slots)) { slot.next = 0; slot.posts = {}; }
    fs.writeFileSync(counterFile, JSON.stringify(st));
    out.steps.post.rolledBackSkipsUsed = counter.take(epoch, pol.community, L.limitFor(cred, pol), "rolled back post", isUsed) !== j;
  }
  // a member proving under a looser policy than the anchored one is refused by the verifier
  { const loose = await snarkjs.groth16.fullProve(L.postInput(tree, index, cred, { ...pol, baseLimit: 60 }, epoch, "loose post", j + 1), L.art("vcrln_d20").wasm, L.art("vcrln_d20").zkey);
    out.steps.post.loosePolicyRejected = (await verifyPost(loose.publicSignals, loose.proof, "loose post")).reason === "public input baseLimit"; }
  // a second device that ignored the counter and reused the index reveals the secret
  { const second = await snarkjs.groth16.fullProve(L.postInput(tree, index, cred, pol, epoch, "second post", j), L.art("vcrln_d20").wasm, L.art("vcrln_d20").zkey);
    const r = await verifyPost(second.publicSignals, second.proof, "second post", seen);
    out.steps.post.reuseRevealsSecret = r.reason === "over limit" && r.secret === BigInt(secret); }
  console.log("post:", out.steps.post);
  out.session = process.env.SESSION || out.ts;
  fs.writeFileSync(path.join(L.ROOT, "data", "vc_demo.json"), JSON.stringify(out, null, 1));
  for (const [k, v] of Object.entries(out.steps.post)) if (typeof v === "boolean") must(v, "post " + k);
  process.exit(0);
})().catch(fail);
