// Paired proving benchmark: our circuit and RLN v2 at depth 20 in one process, alternating A, B, A, B, ... with the
// order inside each pair alternating too, after WARM pairs of warm-up. Drift and background load then hit both
// circuits alike, and the overhead is estimated from per-pair differences. All inputs are built before the first
// timer starts; warm proofs use a compiled witness calculator and the zkey in memory, as in bench_one.js.
//   node scripts/bench_pair.js [pairs]       (appends data/bench_pair.jsonl; SESSION groups processes, PROC names one)
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const { WitnessCalculatorBuilder } = require("circom_runtime");
const L = require("./lib");

const PAIRS = Number(process.argv[2] || 100), WARM = Number(process.env.WARM || 10);
const SESSION = process.env.SESSION || new Date().toISOString();
const PROC = process.env.PROC || `${process.pid}`;
const NAMES = ["vcrln_d20", "rln2_d20"];
const now = () => Number(process.hrtime.bigint()) / 1e6;

(async () => {
  const H = await L.hasher();
  const inputs = {}, ctx = {};
  for (const name of NAMES) {
    const make = L.benchWorkload(H, name);
    inputs[name] = Array.from({ length: WARM + PAIRS }, (_, k) => make(k));
    const art = L.art(name);
    ctx[name] = { wc: await WitnessCalculatorBuilder(fs.readFileSync(art.wasm)),
      zkey: { type: "mem", data: new Uint8Array(fs.readFileSync(art.zkey)) }, vkey: art.vkey };
  }
  const one = async (name, k) => {
    const t0 = now();
    const wtns = { type: "mem", data: await ctx[name].wc.calculateWTNSBin(inputs[name][k], false) };
    const t1 = now();
    const { proof, publicSignals } = await snarkjs.groth16.prove(ctx[name].zkey, wtns);
    const t2 = now();
    return { witnessMs: t1 - t0, proveMs: t2 - t1, totalMs: t2 - t0, proof, publicSignals };
  };
  const diffs = [];
  for (let k = 0; k < WARM + PAIRS; k++) {
    const order = k % 2 ? [NAMES[1], NAMES[0]] : [NAMES[0], NAMES[1]];
    const r = {};
    for (const name of order) r[name] = await one(name, k);
    if (k === WARM + PAIRS - 1)
      for (const name of order) if (!(await snarkjs.groth16.verify(ctx[name].vkey, r[name].publicSignals, r[name].proof))) throw new Error(name + " proof invalid");
    if (k < WARM) continue;
    const rec = { session: SESSION, proc: PROC, pair: k - WARM, first: order[0], ts: new Date().toISOString() };
    for (const name of order) rec[name] = { witnessMs: r[name].witnessMs, proveMs: r[name].proveMs, totalMs: r[name].totalMs };
    fs.appendFileSync(path.join(L.ROOT, "data", "bench_pair.jsonl"), JSON.stringify(rec) + "\n");
    diffs.push(r.vcrln_d20.totalMs - r.rln2_d20.totalMs);
  }
  const m = diffs.reduce((a, b) => a + b, 0) / diffs.length;
  const sd = Math.sqrt(diffs.reduce((a, b) => a + (b - m) ** 2, 0) / (diffs.length - 1));
  console.log(`proc ${PROC}: pairs=${diffs.length} overhead=${m.toFixed(1)} ms (sd ${sd.toFixed(1)})`);
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
