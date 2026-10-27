// Time one circuit configuration in a fresh process: witness generation, Groth16 proving and verification.
//   node scripts/bench_one.js <build name> <timed runs> <pass label>
// The first proof is cold: wasm and zkey are read from disk and the witness program is compiled, as for a member's
// first post. Later proofs reuse one compiled witness calculator and the zkey held in memory, as an open client
// would; WARM of them are discarded before RUNS timed ones.
// Appends one record per run to data/bench_runs.jsonl and a summary line to data/bench.jsonl; all records of one
// bench.sh session carry the same session id.
const fs = require("fs");
const os = require("os");
const path = require("path");
const snarkjs = require("snarkjs");
const { WitnessCalculatorBuilder } = require("circom_runtime");
const L = require("./lib");

const [name, runsArg, pass] = process.argv.slice(2);
const RUNS = Number(runsArg || 30), WARM = Number(process.env.WARM || 10), VERIFY_RUNS = 100;
const SESSION = process.env.SESSION || new Date().toISOString();
const now = () => Number(process.hrtime.bigint()) / 1e6;
const q = (xs, p) => { const s = [...xs].sort((a, b) => a - b), h = (s.length - 1) * p, lo = Math.floor(h); return s[lo] + (s[Math.ceil(h)] - s[lo]) * (h - lo); };
const stats = (xs) => { const m = xs.reduce((a, b) => a + b, 0) / xs.length;
  return { mean: m, sd: Math.sqrt(xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1)), p50: q(xs, 0.5), p95: q(xs, 0.95), min: Math.min(...xs), max: Math.max(...xs) }; };

(async () => {
  const H = await L.hasher();
  const art = L.art(name);
  const info = JSON.parse(fs.readFileSync(path.join(L.ROOT, "build", name, "info.json"), "utf8"));
  const depth = Number(name.match(/_d(\d+)/)[1]);
  const makeInput = L.benchWorkload(H, name);
  const inputs = Array.from({ length: WARM + RUNS + 1 }, (_, k) => makeInput(k));  // built before any timer starts

  const log = (rec) => fs.appendFileSync(path.join(L.ROOT, "data", "bench_runs.jsonl"), JSON.stringify({ session: SESSION, name, pass, ...rec }) + "\n");
  // cold proof: files from disk, witness program compiled inside the timed region
  let proof, publicSignals;
  { const t0 = now();
    const wtns = { type: "mem" };
    await snarkjs.wtns.calculate(inputs[0], art.wasm, wtns);
    const t1 = now();
    ({ proof, publicSignals } = await snarkjs.groth16.prove(art.zkey, wtns));
    const t2 = now();
    log({ cold: true, run: -1, witnessMs: t1 - t0, proveMs: t2 - t1, totalMs: t2 - t0, ts: new Date().toISOString() }); }
  // warm proofs: compiled calculator and zkey reused
  const wc = await WitnessCalculatorBuilder(fs.readFileSync(art.wasm));
  const zkey = { type: "mem", data: new Uint8Array(fs.readFileSync(art.zkey)) };
  const wit = [], prv = [], tot = [];
  for (let k = 1; k <= WARM + RUNS; k++) {
    const t0 = now();
    const wtns = { type: "mem", data: await wc.calculateWTNSBin(inputs[k], false) };  // no sanity check, as snarkjs's own path
    const t1 = now();
    ({ proof, publicSignals } = await snarkjs.groth16.prove(zkey, wtns));
    const t2 = now();
    if (k > WARM) {
      wit.push(t1 - t0); prv.push(t2 - t1); tot.push(t2 - t0);
      log({ cold: false, run: k - WARM - 1, witnessMs: t1 - t0, proveMs: t2 - t1, totalMs: t2 - t0, ts: new Date().toISOString() });
    }
  }
  const ver = [];
  for (let k = 0; k < VERIFY_RUNS; k++) {
    const t0 = now();
    const ok = await snarkjs.groth16.verify(art.vkey, publicSignals, proof);
    ver.push(now() - t0);
    if (!ok) throw new Error("proof did not verify");
  }
  const out = { session: SESSION, name, pass, warm: WARM, depth, constraints: info.constraints, publicSignals: publicSignals.length, zkeyBytes: info.zkeyBytes,
    wasmBytes: info.wasmBytes, runs: RUNS, witness: stats(wit), prove: stats(prv), total: stats(tot), verify: stats(ver),
    rssMB: Math.round(process.memoryUsage().rss / 2 ** 20), cpu: os.cpus()[0].model.trim(), cores: os.cpus().length,
    node: process.version, snarkjs: JSON.parse(fs.readFileSync(path.join(L.ROOT, "node_modules", "snarkjs", "package.json"), "utf8")).version,
    ts: new Date().toISOString() };
  fs.appendFileSync(path.join(L.ROOT, "data", "bench.jsonl"), JSON.stringify(out) + "\n");
  console.log(`${name} [${pass}] constraints=${out.constraints} prove=${out.total.mean.toFixed(1)}±${out.total.sd.toFixed(1)} ms (p95 ${out.total.p95.toFixed(1)}) verify=${out.verify.mean.toFixed(2)} ms`);
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
