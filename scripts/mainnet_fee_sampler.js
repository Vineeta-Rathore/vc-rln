// Read-only mainnet pricing of transactions measured on OP Sepolia (data/tx_inputs.json: calldata of one transaction
// per operation; calldata size depends only on the leaf count). Every INTERVAL seconds it
// records: OP Mainnet base fee, suggested tip and GasPriceOracle.getL1Fee(tx) (Fjord FastLZ rule) plus the
// operator fee if the chain exposes it; Arbitrum One base fee and NodeInterface.gasEstimateL1Component(tx);
// Ethereum base fee and suggested tip. No transaction is sent and no key is used.
//   SAMPLES=72 INTERVAL=600 node scripts/mainnet_fee_sampler.js     (appends data/mainnet_fees.jsonl)
// FEE_OUTPUT selects a separate JSONL file; RUN_ID labels a new collection without changing historical rows.
const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
const L = require("./lib");

const ENV_FILE = process.env.ENV_FILE || path.join(L.ROOT, ".env");  // testnet-only key and RPC URLs; never printed
const ENV = { ...(require("dotenv").config({ path: ENV_FILE, processEnv: {} }).parsed || {}), ...process.env };
const RPC = {
  op: ENV.OPMAIN_RPC || "https://mainnet.optimism.io",
  arb: ENV.ARB1_RPC || "https://arb1.arbitrum.io/rpc",
  eth: ENV.ETH_MAINNET_RPC || "https://ethereum-rpc.publicnode.com",
  opSepolia: ENV.OP_RPC || "https://sepolia.optimism.io",
};
const SAMPLES = Number(process.env.SAMPLES || 72), INTERVAL = Number(process.env.INTERVAL || 600);
const OUT = process.env.FEE_OUTPUT || path.join(L.ROOT, "data", "mainnet_fees.jsonl"), TXS = path.join(L.ROOT, "data", "tx_inputs.json");
const GPO = new ethers.Contract("0x420000000000000000000000000000000000000F", [
  "function getL1Fee(bytes) view returns (uint256)", "function getL1GasUsed(bytes) view returns (uint256)",
  "function getOperatorFee(uint256) view returns (uint256)"]);
const NODE = new ethers.Contract("0x00000000000000000000000000000000000000C8", [
  "function gasEstimateL1Component(address to, bool contractCreation, bytes data) payable returns (uint64 gasEstimateForL1, uint256 baseFee, uint256 l1BaseFeeEstimate)"]);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const scrub = (e) => String(e && e.message || e).replace(/https?:\/\/\S+/g, "<rpc>").slice(0, 160);

async function loadTxs() {  // the calldata of one representative transaction per operation (OP Sepolia run)
  if (fs.existsSync(TXS)) return JSON.parse(fs.readFileSync(TXS, "utf8"));
  const recs = fs.readFileSync(path.join(L.ROOT, "data", "testnet.jsonl"), "utf8").trim().split("\n").map(JSON.parse)
    .filter((r) => r.net === "opSepolia");
  const pick = (op, n, phase) => recs.find((r) => r.op === op && r.n === n && (!phase || r.phase === phase));
  const chosen = [["addLeaves", 1, "steady"], ["addLeaves", 16, "steady"], ["addLeaves", 128, "steady"], ["revokeLeaves", 1], ["PostBoard.post", 1]]
    .map(([op, n, ph]) => pick(op, n, ph));
  const p = new ethers.JsonRpcProvider(RPC.opSepolia, 11155420, { staticNetwork: true });
  const out = [];
  for (const r of chosen) {
    const tx = await p.getTransaction(r.txHash);
    out.push({ op: r.op, n: r.n, to: tx.to, data: tx.data, gasUsedOp: r.gasUsed, txHash: r.txHash });
  }
  const arb = fs.readFileSync(path.join(L.ROOT, "data", "testnet.jsonl"), "utf8").trim().split("\n").map(JSON.parse).filter((r) => r.net === "arbSepolia");
  for (const o of out) { const m = arb.find((r) => r.op === o.op && r.n === o.n && (r.phase === "steady" || !r.phase)); o.gasUsedArb = m ? m.gasUsed : null; }
  fs.writeFileSync(TXS, JSON.stringify(out, null, 1));
  return out;
}

(async () => {
  const txs = await loadTxs();
  const op = new ethers.JsonRpcProvider(RPC.op, 10, { staticNetwork: true });
  const arb = new ethers.JsonRpcProvider(RPC.arb, 42161, { staticNetwork: true });
  const eth = new ethers.JsonRpcProvider(RPC.eth, 1, { staticNetwork: true });
  for (let s = 0; s < SAMPLES; s++) {
    const rec = { sample: s, ts: new Date().toISOString(), ...(process.env.RUN_ID ? { run: process.env.RUN_ID } : {}), op: {}, arb: {}, eth: {} };
    try {
      const b = await op.getBlock("latest");
      rec.op.block = b.number; rec.op.baseFeeWei = b.baseFeePerGas.toString();
      rec.op.tipWei = BigInt(await op.send("eth_maxPriorityFeePerGas", [])).toString();
      rec.op.tx = [];
      for (const t of txs) {
        const unsigned = ethers.Transaction.from({ type: 2, chainId: 10, nonce: 1000, to: t.to, data: t.data, gasLimit: BigInt(Math.ceil(t.gasUsedOp * 1.2)),
          maxFeePerGas: BigInt(rec.op.baseFeeWei) * 2n + BigInt(rec.op.tipWei), maxPriorityFeePerGas: BigInt(rec.op.tipWei) }).unsignedSerialized;
        const g = GPO.connect(op);
        const x = { op: t.op, n: t.n, l1FeeWei: (await g.getL1Fee(unsigned)).toString(), l1GasUsed: (await g.getL1GasUsed(unsigned)).toString() };
        try { x.operatorFeeWei = (await g.getOperatorFee(t.gasUsedOp)).toString(); } catch (e) { x.operatorFeeWei = null; }
        rec.op.tx.push(x);
      }
    } catch (e) { rec.op.error = scrub(e); }
    try {
      const b = await arb.getBlock("latest");
      rec.arb.block = b.number; rec.arb.baseFeeWei = b.baseFeePerGas.toString(); rec.arb.tx = [];
      for (const t of txs) {
        const r = await NODE.connect(arb).gasEstimateL1Component.staticCall(t.to, false, t.data);
        rec.arb.tx.push({ op: t.op, n: t.n, gasEstimateForL1: r[0].toString(), l1BaseFeeEstimateWei: r[2].toString() });
      }
    } catch (e) { rec.arb.error = scrub(e); }
    try {
      const b = await eth.getBlock("latest");
      rec.eth.block = b.number; rec.eth.baseFeeWei = b.baseFeePerGas.toString();
      rec.eth.tipWei = BigInt(await eth.send("eth_maxPriorityFeePerGas", [])).toString();
    } catch (e) { rec.eth.error = scrub(e); }
    fs.appendFileSync(OUT, JSON.stringify(rec) + "\n");
    console.log(`sample ${s} ${rec.ts} op=${rec.op.error ? "ERR " + rec.op.error : rec.op.baseFeeWei} arb=${rec.arb.error ? "ERR " + rec.arb.error : rec.arb.baseFeeWei} eth=${rec.eth.error ? "ERR " + rec.eth.error : rec.eth.baseFeeWei}`);
    if (s < SAMPLES - 1) await sleep(INTERVAL * 1000);
  }
  process.exit(0);
})().catch((e) => { console.error(scrub(e)); process.exit(1); });
