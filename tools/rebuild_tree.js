// Replays each registry's LeavesAdded and LeavesRevoked events, rebuilds the issuer's depth-20 Poseidon tree and
// compares every root it reaches with the root in the event and the final one with currentRoot(issuer). Read-only.
// Old logs need an endpoint that serves them; the defaults in common.js do, but some free endpoints return an empty
// list or "pruned history" for old blocks.
//   node tools/rebuild_tree.js [network]
const fs = require("fs");
const path = require("path");
const { Contract } = require("ethers");
const { hasher, Tree, provider, retry } = require("./common");

const ABI = ["event LeavesAdded(address indexed issuer, uint256 firstIndex, uint256[] leaves, uint256 root)",
  "event LeavesRevoked(address indexed issuer, uint256[] indices, uint256 root)",
  "function currentRoot(address issuer) view returns (uint256)"];
const regs = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "data", "registries.json"), "utf8"))
  .filter((r) => !process.argv[2] || r.network === process.argv[2]);
const STEP = Number(process.env.LOG_STEP || 2000);

(async () => {
  const H = await hasher();
  let failed = 0;
  for (const r of regs) {
    const prov = provider(r.network), reg = new Contract(r.registry, ABI, prov);
    try {
      const head = await retry(() => prov.getBlockNumber()), logs = [];
      // only this issuer's events: anyone can publish under their own address on a public registry
      for (let from = r.deployBlock; from <= head; from += STEP) {
        const to = Math.min(head, from + STEP - 1);
        logs.push(...await retry(() => reg.queryFilter(reg.filters.LeavesAdded(r.issuer), from, to)),
          ...await retry(() => reg.queryFilter(reg.filters.LeavesRevoked(r.issuer), from, to)));
      }
      logs.sort((a, b) => a.blockNumber - b.blockNumber || a.index - b.index);
      if (!logs.length) { console.log(`${r.network}: no events returned; try an endpoint that serves old logs`); failed++; continue; }
      const tree = new Tree(H, 20);
      let mism = 0;
      for (const ev of logs) {
        if (ev.fragment.name === "LeavesAdded") {
          if (Number(ev.args.firstIndex) !== tree.leaves.length) mism++;  // the batch must start where the tree ends
          ev.args.leaves.forEach((l) => tree.insert(l));
        } else ev.args.indices.forEach((i) => tree.revoke(Number(i)));
        if (tree.root() !== ev.args.root) mism++;
      }
      const issuer = r.issuer, onChain = await retry(() => reg.currentRoot(issuer));
      const ok = mism === 0 && onChain === tree.root();
      if (!ok) failed++;
      console.log(`${ok ? "PASS" : "FAIL"}  ${r.network}: ${logs.length} events, ${tree.leaves.length} leaves, every event root reproduced: ${mism === 0}, final root equals currentRoot: ${onChain === tree.root()}`);
    } catch (e) {
      failed++;
      console.log(`UNREACHED  ${r.network}: the endpoint did not answer (${String(e.message || e).replace(/https?:\/\/\S+/g, "<rpc>").slice(0, 80)}); rerun or set its *_RPC variable`);
    }
  }
  process.exit(failed ? 1 : 0);
})();
