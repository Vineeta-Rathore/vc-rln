// Where the depth-20 circuit's constraints go (Section V-A): compiles circuits/vcrln.circom as is, without the
// per-community pseudonym, also without the in-circuit external nullifier (a public value instead, as in RLN), and
// with a second share and nullifier for a platform-wide cap (Section VI),
// and the reference RLN v2 circuit at depths 10 and 20 for its per-level cost. Variants are generated from the
// circuit source into build/variants; only the R1CS is compiled. Writes data/constraint_breakdown.json.
//   CIRCOM=<path to circom 2.2.3> node scripts/constraint_breakdown.js
const fs = require("fs");
const path = require("path");
const { execFileSync } = require("child_process");
const L = require("./lib");

const CIRCOM = process.env.CIRCOM || "circom";
const OUT = path.join(L.ROOT, "build", "variants");
const PUBLIC = "root, schema, epoch, community, x, ageCutoff, seniorityCutoff, baseLimit, verifiedBonus, seniorityBonus, mode";
fs.mkdirSync(OUT, { recursive: true });

const src = fs.readFileSync(path.join(L.ROOT, "circuits", "vcrln.circom"), "utf8").replace(/\r\n/g, "\n");
const edit = (s, from, to) => { if (!s.includes(from)) throw new Error("variant edit not found: " + from.slice(0, 40)); return s.replace(from, to); };
const PSEUDONYM = `    component pH = Poseidon(2);
    pH.inputs[0] <== secret;
    pH.inputs[1] <== community;
    pseudonym <== mode * pH.out;`;
const EXT = `    component ext = Poseidon(2);
    ext.inputs[0] <== epoch;
    ext.inputs[1] <== community;
    component a1H = Poseidon(3);
    a1H.inputs[0] <== secret;
    a1H.inputs[1] <== ext.out;`;
const noPseudo = edit(src, PSEUDONYM, "    pseudonym <== 0 * mode;");
const noExt = edit(noPseudo, EXT, `    component a1H = Poseidon(3);
    a1H.inputs[0] <== secret;
    a1H.inputs[1] <== epoch + community;  // stands in for a public external nullifier (as in RLN)`);
// a platform-wide cap across communities (Section VI): a second share and nullifier bound to the epoch alone, with its
// own message index below a public cap
const cap = edit(edit(src, "    signal output pseudonym;", `    signal output pseudonym;
    signal input messageId2;
    signal input capLimit;
    signal output y2;
    signal output nullifier2;`), PSEUDONYM, `${PSEUDONYM}

    component rj2 = Num2Bits(16);  rj2.in <== messageId2;
    component rc2 = Num2Bits(16);  rc2.in <== capLimit;
    component j2Ok = LessThan(16);
    j2Ok.in[0] <== messageId2;
    j2Ok.in[1] <== capLimit;
    j2Ok.out === 1;
    component a2H = Poseidon(3);
    a2H.inputs[0] <== secret;
    a2H.inputs[1] <== epoch;  // the platform-wide external nullifier: the epoch alone
    a2H.inputs[2] <== messageId2;
    y2 <== secret + a2H.out * x;
    component n2H = Poseidon(1);
    n2H.inputs[0] <== a2H.out;
    nullifier2 <== n2H.out;`);

function constraints(name, main) {  // circom's own count of non-linear constraints (snarkjs r1cs info also counts linear ones)
  fs.writeFileSync(path.join(OUT, `main_${name}.circom`), main);
  const log = execFileSync(CIRCOM, [path.join(OUT, `main_${name}.circom`), "--r1cs", "--O2", "-l", path.join(L.ROOT, "node_modules"),
    "-l", OUT, "-l", path.join(L.ROOT, "circuits"), "-l", path.join(L.ROOT, "circuits", "baseline"), "-o", OUT], { encoding: "utf8" });
  return Number(/non-linear constraints: (\d+)/.exec(log)[1]);
}
const vmain = (file) => `pragma circom 2.1.6;\ninclude "${file}";\ncomponent main {public [${PUBLIC}]} = VCRLN(20);\n`;
const rlnMain = (depth) => `pragma circom 2.1.0;\ninclude "rln_template.circom";\ncomponent main { public [x, externalNullifier] } = RLN(${depth}, 16);\n`;
fs.writeFileSync(path.join(OUT, "v_full.circom"), src);
fs.writeFileSync(path.join(OUT, "v_nopseudo.circom"), noPseudo);
fs.writeFileSync(path.join(OUT, "v_noext.circom"), noExt);
fs.writeFileSync(path.join(OUT, "v_cap.circom"), cap);
// the baseline file declares its own main component; the template is reused without it
fs.writeFileSync(path.join(OUT, "rln_template.circom"),
  fs.readFileSync(path.join(L.ROOT, "circuits", "baseline", "rln.circom"), "utf8").replace(/\r\n/g, "\n").replace(/^component main.*$/m, ""));

const full = constraints("v_full", vmain("v_full.circom"));
const nop = constraints("v_nopseudo", vmain("v_nopseudo.circom"));
const noe = constraints("v_noext", vmain("v_noext.circom"));
const withCap = constraints("v_cap", vmain("v_cap.circom").replace("mode]}", "mode, capLimit]}"));
const rln20 = constraints("rln_d20", rlnMain(20)), rln10 = constraints("rln_d10", rlnMain(10));
const rlnLevel = (rln20 - rln10) / 10;
const ourLevel = (JSON.parse(fs.readFileSync(path.join(L.ROOT, "build", "vcrln_d32", "info.json"))).constraints
  - JSON.parse(fs.readFileSync(path.join(L.ROOT, "build", "vcrln_d10", "info.json"))).constraints) / 22;
const merkle = 20 * (ourLevel - rlnLevel);
const out = {
  depth: 20,
  note: "non-linear constraints with circom --O2; variants in build/variants (generated from circuits/vcrln.circom by scripts/constraint_breakdown.js)",
  vcrln_full: full, without_pseudonym: nop, without_pseudonym_and_in_circuit_external_nullifier: noe, rln_v2_reference: rln20,
  cost: { pseudonym: full - nop, in_circuit_external_nullifier: nop - noe, credential_leaf_and_policy: noe - rln20,
    merkle_saving_vs_rln_v2: merkle, credential_leaf_and_policy_gross: noe - rln20 - merkle, platform_wide_cap: withCap - full },
  merkle_per_level: { ours: ourLevel, rln_v2: rlnLevel,
    note: `rln.circom compiled with circom --O2 at depths 10 and 20: ${rln10} and ${rln20} non-linear constraints` },
};
fs.writeFileSync(path.join(L.ROOT, "data", "constraint_breakdown.json"), JSON.stringify(out, null, 1) + "\n");
console.log(JSON.stringify(out));
