// Revocation visibility: on one network deploy ERC-1056 and the ring registry, publish 32 leaves,
// then make REPS single-leaf revocations at random gaps of GAP_MIN..GAP_MAX s (so send times are not locked to the
// block clock). For each one we record the time until the sender's RPC returns the receipt and the time until a
// reader on a different RPC provider sees the new root. The reader polls on a fixed schedule (one request every
// POLL_MS, not waiting for the previous reply), so the resolution is POLL_MS plus that provider's latency.
//   NET=opSepolia node scripts/revoke_lag.js        (appends data/revocation_lag.jsonl)
const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
const L = require("./lib");

const fail = L.guardSecrets();  // errors are printed with RPC URLs and long hex strings masked

const ENV_FILE = process.env.ENV_FILE || path.join(L.ROOT, ".env");  // testnet-only key and RPC URLs; never printed
const ENV = { ...(require("dotenv").config({ path: ENV_FILE, processEnv: {} }).parsed || {}), ...process.env };
// sender and reader always use different providers
const SENDER = { sepolia: ENV.SEPOLIA_RPC_URL, opSepolia: ENV.OP_RPC || "https://optimism-sepolia-rpc.publicnode.com",
  arbSepolia: ENV.ARB_RPC || "https://sepolia-rollup.arbitrum.io/rpc" };
const READER = { sepolia: "https://ethereum-sepolia-rpc.publicnode.com", opSepolia: "https://optimism-sepolia.drpc.org",
  arbSepolia: "https://arbitrum-sepolia-rpc.publicnode.com" };
const CHAIN = { sepolia: 11155111, opSepolia: 11155420, arbSepolia: 421614 };
const NET = process.env.NET;
const REPS = Number(process.env.REPS || 20), GAP_MIN = 120, GAP_MAX = 240, POLL_MS = 200, TIMEOUT_MS = 180000;
const OUT = path.join(L.ROOT, "data", "revocation_lag.jsonl");
const RUN = new Date().toISOString();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Number(process.hrtime.bigint()) / 1e6;
const artifact = (n) => JSON.parse(fs.readFileSync(path.join(L.ROOT, "artifacts", "contracts", n + ".sol", n + ".json"), "utf8"));
async function retry(fn, tries = 5) {
  for (let k = 1; ; k++) { try { return await fn(); } catch (e) { if (k >= tries) throw e; await sleep(1000 * k); } }
}

let provider, wallet, me, nonce;
async function receiptOf(hash, t0) {
  while (now() - t0 < TIMEOUT_MS) {
    const r = await retry(() => provider.send("eth_getTransactionReceipt", [hash]));
    if (r) return r;
    await sleep(POLL_MS);
  }
  throw new Error("receipt timeout");
}
async function sendTx(to, data, gasLimit) {
  const fee = await retry(() => provider.getFeeData());
  try { gasLimit = (await provider.estimateGas({ from: me, to, data }) * 13n) / 10n; } catch (e) { /* keep the fixed limit */ }
  const signed = await wallet.signTransaction({ to, data, gasLimit, nonce: nonce++, chainId: CHAIN[NET], type: 2,
    maxFeePerGas: fee.maxFeePerGas * 2n, maxPriorityFeePerGas: fee.maxPriorityFeePerGas ?? 1000000n });
  const t0 = now();
  const hash = await provider.send("eth_sendRawTransaction", [signed]);
  return { hash, t0, tSent: now() };
}
// fixed-schedule polling of the reader; resolves with the time the first reply showing `want` arrived
function watchRoot(reg, t0, want) {
  return new Promise((resolve) => {
    let done = false;
    const tick = setInterval(() => {
      if (done) return;
      if (now() - t0 > TIMEOUT_MS) { done = true; clearInterval(tick); resolve(null); return; }
      reg.currentRoot(me).then((r) => { if (!done && r === want) { done = true; clearInterval(tick); resolve(now() - t0); } }, () => {});
    }, POLL_MS);
  });
}

(async () => {
  if (!SENDER[NET]) throw new Error("set NET to sepolia | opSepolia | arbSepolia (and its RPC in the .env)");
  provider = new ethers.JsonRpcProvider(SENDER[NET], CHAIN[NET], { staticNetwork: true });
  const reader = new ethers.JsonRpcProvider(READER[NET], CHAIN[NET], { staticNetwork: true });
  wallet = new ethers.Wallet(L.privateKey(ENV), provider);
  me = await wallet.getAddress();
  nonce = await retry(() => provider.getTransactionCount(me, "pending"));
  const bal = await retry(() => provider.getBalance(me));
  console.log(`net=${NET} balance=${ethers.formatEther(bal)} ETH reps=${REPS}`);
  if (bal < ethers.parseEther("0.0005")) throw new Error("balance too low");

  const deploy = async (name, args) => {
    const a = artifact(name);
    const data = a.bytecode + new ethers.ContractFactory(a.abi, a.bytecode).interface.encodeDeploy(args).slice(2);
    const { hash, t0 } = await sendTx(null, data, 2000000n);
    return (await receiptOf(hash, t0)).contractAddress;
  };
  const didAddr = await deploy("EthereumDIDRegistry", []);
  const regAddr = await deploy("IssuerRootRegistry", [didAddr]);
  const a = artifact("IssuerRootRegistry"), iface = new ethers.Interface(a.abi);
  const regR = new ethers.Contract(regAddr, a.abi, reader);

  const H = await L.hasher();
  const tree = new L.Tree(H, 20);
  const leaves = Array.from({ length: 32 }, () => L.randField());
  leaves.forEach((l) => tree.insert(l));
  { const { hash, t0 } = await sendTx(regAddr, iface.encodeFunctionData("addLeaves", [me, leaves, tree.root()]), 2500000n);
    await receiptOf(hash, t0); }
  // wait until the reader has caught up before the first timed revocation
  while ((await retry(() => regR.currentRoot(me))) !== tree.root()) await sleep(1000);

  for (let rep = 0; rep < REPS; rep++) {
    await sleep((GAP_MIN + Math.random() * (GAP_MAX - GAP_MIN)) * 1000);
    tree.revoke(rep + 1);
    const want = tree.root();
    const { hash, t0, tSent } = await sendTx(regAddr, iface.encodeFunctionData("revokeLeaves", [me, [rep + 1], want]), 400000n);
    const seen = watchRoot(regR, t0, want);
    const raw = await receiptOf(hash, t0);
    const tRc = now();
    if (raw.status !== "0x1") throw new Error("revocation reverted");
    const visibleMs = await seen;
    const rec = { run: RUN, net: NET, rep, txHash: hash, block: Number(raw.blockNumber), gasUsed: Number(BigInt(raw.gasUsed)),
      sendMs: tSent - t0, inclusionMs: tRc - t0, visibleMs, pollMs: POLL_MS, reader: new URL(READER[NET]).host,
      ts: new Date().toISOString() };
    fs.appendFileSync(OUT, JSON.stringify(rec) + "\n");
    console.log(`${NET} rep=${rep} incl=${rec.inclusionMs.toFixed(0)}ms visible=${visibleMs == null ? "timeout" : visibleMs.toFixed(0) + "ms"}`);
  }
  console.log("done", NET);
  process.exit(0);
})().catch(fail);
