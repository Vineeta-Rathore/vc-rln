// Sample proofs for tools/verify_proofs.js: three posts of one member under one policy (indices 0 and 1, and a second
// post with index 0, so a reader can recover the secret from the reused index) and one RLN v2 proof.
// Writes proofs/*.json with the proof, the public signals and the inputs a verifier sees.
//   node scripts/export_proofs.js
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const L = require("./lib");

const OUT = path.join(L.ROOT, "proofs");
const big = (o) => JSON.parse(JSON.stringify(o, (k, v) => (typeof v === "bigint" ? v.toString() : v)));

(async () => {
  fs.mkdirSync(OUT, { recursive: true });
  const H = await L.hasher();
  const tree = new L.Tree(H, 20);
  for (let i = 0; i < 7; i++) tree.insert(L.randField());
  const today = L.dayNumber("2026-10-26");
  const schema = H(L.postHash("IC4 SocialAccountCredential v1"));
  const policy = { community: L.postHash("community:general"), ageCutoff: L.dayNumber("2008-10-26"), seniorityCutoff: today - 30,
    baseLimit: 1, verifiedBonus: 4, seniorityBonus: 5, mode: 0 };
  const cred = L.makeCredential(H, { secret: L.randField(), birthDate: L.dayNumber("1995-03-14"), accountCreated: L.dayNumber("2024-01-10"),
    verifiedHuman: 1, schema, salt: L.randField() });
  const idx = tree.insert(cred.leaf);
  const epoch = L.epochOfDay(today);  // hour index of the day's start, hours since 1970 as the clock counts
  const posts = [["post_index0", "hello, community", 0], ["post_index1", "a second post", 1], ["post_index0_reused", "a third post, index reused", 0]];
  for (const [file, text, j] of posts) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(L.postInput(tree, idx, cred, policy, epoch, text, j), L.art("vcrln_d20").wasm, L.art("vcrln_d20").zkey);
    fs.writeFileSync(path.join(OUT, file + ".json"), JSON.stringify(big({ circuit: "vcrln_d20", text, policy, schema, epoch, root: tree.root(),
      publicSignalOrder: L.PUB, publicSignals, proof }), null, 1));
  }
  const s = L.randField(), iB = tree.insert(H(H(s), 10));
  const { pathElements, pathIndex } = tree.path(iB);
  const r = await snarkjs.groth16.fullProve({ identitySecret: s, userMessageLimit: 10, messageId: 0, pathElements, identityPathIndex: pathIndex,
    x: L.postHash("rln v2 post"), externalNullifier: H(BigInt(epoch), policy.community) }, L.art("rln2_d20").wasm, L.art("rln2_d20").zkey);
  fs.writeFileSync(path.join(OUT, "rln_v2_reference.json"), JSON.stringify(big({ circuit: "rln2_d20", publicSignals: r.publicSignals, proof: r.proof }), null, 1));
  // the secret behind the reused index, so the recovery check has something to compare against
  fs.writeFileSync(path.join(OUT, "expected_identity_commitment.json"), JSON.stringify(big({ idCommitment: cred.idCommitment }), null, 1));
  console.log("proofs written to", OUT);
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
