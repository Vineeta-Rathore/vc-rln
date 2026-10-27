// Client-side tree cost at the modeled platform size: building the issuer's depth-20 tree from M leaves (what a
// member computes once from the event log to keep its own copy), an incremental insertion afterwards (one per new
// leaf in the log), and checking a Merkle path against the current root (20 hashes). Builds are repeated BUILDS
// times and insertions INSERTS times; the medians and ranges are recorded.
//   node scripts/bench_tree.js [M]         (appends data/bench_tree.jsonl)
const fs = require("fs");
const path = require("path");
const L = require("./lib");

const M = Number(process.argv[2] || 100000), BUILDS = Number(process.env.BUILDS || 3), INSERTS = Number(process.env.INSERTS || 200);
const SESSION = process.env.SESSION || new Date().toISOString();
const now = () => Number(process.hrtime.bigint()) / 1e6;
const med = (xs) => { const s = [...xs].sort((a, b) => a - b); return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2; };

(async () => {
  const H = await L.hasher();
  const leaves = Array.from({ length: M }, () => L.randField());
  const builds = [];
  let tree;
  for (let b = 0; b < BUILDS; b++) {
    tree = new L.Tree(H, 20);
    for (const l of leaves) tree.insert(l);
    const t = now();
    tree.root();
    builds.push(now() - t);
  }
  const inserts = [];
  for (let k = 0; k < INSERTS; k++) { const l = L.randField(), t = now(); tree.insert(l); inserts.push(now() - t); }
  const idx = Math.floor(M / 2), { pathElements, pathIndex } = tree.path(idx), cur = tree.root();
  const reps = 200;
  let t = now(), ok = true;
  for (let r = 0; r < reps; r++) {
    let h = tree.leaves[idx];
    for (let l = 0; l < 20; l++) h = pathIndex[l] ? H(pathElements[l], h) : H(h, pathElements[l]);
    ok = ok && h === cur;
  }
  const verifyPathMs = (now() - t) / reps;
  if (!ok) throw new Error("path check failed");
  const rec = { session: SESSION, leaves: M, builds: BUILDS, buildMs: med(builds), buildMinMs: Math.min(...builds), buildMaxMs: Math.max(...builds),
    inserts: INSERTS, insertMs: med(inserts), insertMaxMs: Math.max(...inserts), verifyPathMs, eventBytesPerLeaf: 32, ts: new Date().toISOString() };
  fs.appendFileSync(path.join(L.ROOT, "data", "bench_tree.jsonl"), JSON.stringify(rec) + "\n");
  console.log(`M=${M}: build ${rec.buildMs.toFixed(0)} ms (median of ${BUILDS}), insert ${rec.insertMs.toFixed(2)} ms (median of ${INSERTS}), path check ${verifyPathMs.toFixed(2)} ms`);
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
