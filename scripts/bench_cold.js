// One cold proof in a fresh process, as a member's first post after the client starts: the wasm and zkey are read
// from disk and the witness program is compiled inside the timed region. The input is built before the timer.
// run_cpu_suite.sh starts it repeatedly, alternating the circuits.
//   node scripts/bench_cold.js <build name>      (appends data/bench_cold.jsonl)
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const L = require("./lib");

const name = process.argv[2];
const SESSION = process.env.SESSION || new Date().toISOString();
const now = () => Number(process.hrtime.bigint()) / 1e6;

(async () => {
  const H = await L.hasher();
  const art = L.art(name);
  const input = L.benchWorkload(H, name)(0);
  // PREWARM_MS > 0 keeps the processor busy before the timer, to separate frequency ramp-up from the cold start
  const PREWARM_MS = Number(process.env.PREWARM_MS || 0);
  for (const end = now() + PREWARM_MS; now() < end;) H(1n, 2n);
  const t0 = now();
  const wtns = { type: "mem" };
  await snarkjs.wtns.calculate(input, art.wasm, wtns);
  const t1 = now();
  const { proof, publicSignals } = await snarkjs.groth16.prove(art.zkey, wtns);
  const t2 = now();
  if (!(await snarkjs.groth16.verify(art.vkey, publicSignals, proof))) throw new Error("cold proof invalid");
  const sizes = { wasmBytes: fs.statSync(art.wasm).size, zkeyBytes: fs.statSync(art.zkey).size };
  fs.appendFileSync(path.join(L.ROOT, "data", "bench_cold.jsonl"), JSON.stringify({ session: SESSION, name, prewarmMs: PREWARM_MS, witnessMs: t1 - t0,
    proveMs: t2 - t1, totalMs: t2 - t0, ...sizes, ts: new Date().toISOString() }) + "\n");
  console.log(`${name} cold ${(t2 - t0).toFixed(0)} ms`);
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
