// Verifies the sample Groth16 proofs against the verification keys, checks that the public signals carry the stated
// post hash, policy and epoch, that a changed signal fails, and that the two posts with a reused index reveal a
// secret whose Poseidon hash is the member's identity commitment.
//   node tools/verify_proofs.js
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { postHash, hasher, recoverSecret } = require("./common");

const dir = path.join(__dirname, "..");
const load = (f) => JSON.parse(fs.readFileSync(path.join(dir, f), "utf8"));
let failed = 0;
const check = (name, ok) => { console.log(`${ok ? "PASS" : "FAIL"}  ${name}`); if (!ok) failed++; };

(async () => {
  const vk = { vcrln_d20: load("build/vcrln_d20/vkey.json"), rln2_d20: load("build/rln2_d20/vkey.json") };
  const posts = ["post_index0", "post_index1", "post_index0_reused"].map((f) => load(`proofs/${f}.json`));
  for (const p of posts) {
    check(`proof verifies: "${p.text}"`, await snarkjs.groth16.verify(vk.vcrln_d20, p.publicSignals, p.proof));
    const s = Object.fromEntries(p.publicSignalOrder.map((k, i) => [k, BigInt(p.publicSignals[i])]));
    check(`  public signals carry H(post), epoch, root, schema and the whole policy`, s.x === postHash(p.text)
      && s.epoch === BigInt(p.epoch) && s.root === BigInt(p.root) && s.schema === BigInt(p.schema)
      && ["community", "ageCutoff", "seniorityCutoff", "baseLimit", "verifiedBonus", "seniorityBonus", "mode"].every((k) => s[k] === BigInt(p.policy[k])));
  }
  const ps = posts[0].publicSignals.slice();
  ps[7] = (BigInt(ps[7]) + 1n).toString();
  check("a changed post hash fails", !(await snarkjs.groth16.verify(vk.vcrln_d20, ps, posts[0].proof)));
  const ref = load("proofs/rln_v2_reference.json");
  check("RLN v2 reference proof verifies", await snarkjs.groth16.verify(vk.rln2_d20, ref.publicSignals, ref.proof));

  const sig = (p) => Object.fromEntries(p.publicSignalOrder.map((k, i) => [k, BigInt(p.publicSignals[i])]));
  const a = sig(posts[0]), b = sig(posts[1]), c = sig(posts[2]);
  check("different indices give different nullifiers", a.nullifier !== b.nullifier);
  check("a reused index gives the same nullifier", a.nullifier === c.nullifier);
  const H = await hasher();
  const s = recoverSecret(a.x, a.y, c.x, c.y);
  check("the two shares reveal the secret behind the identity commitment", H(s) === BigInt(load("proofs/expected_identity_commitment.json").idCommitment));
  console.log(failed ? `${failed} checks failed` : "all checks passed");
  process.exit(failed ? 1 : 0);
})();
