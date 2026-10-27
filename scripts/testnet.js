// Live runs on one network (NET = sepolia | opSepolia | arbSepolia): deploy ERC-1056, the ring root registry and
// the per-root comparison registry; first publication, ring fill (15 single-leaf publications), then steady-state
// batches of 1, 16 and 128 leaves; ten timed revocations (send -> receipt, send -> the same endpoint reports the new
// root; the revocation lag the paper cites comes from scripts/revoke_lag.js, which reads through a second provider);
// four publications on the comparison registry; three posts through the on-chain baseline. The receipts' rollup fee
// fields are saved. The key and RPC URLs come from an .env file that is never printed.
//   NET=opSepolia node scripts/testnet.js       (appends data/testnet.jsonl)
const fs = require("fs");
const path = require("path");
const { ethers } = require("ethers");
const snarkjs = require("snarkjs");
const L = require("./lib");
const fail = L.guardSecrets();

const ENV_FILE = process.env.ENV_FILE || path.join(L.ROOT, ".env");  // testnet-only key and RPC URLs; never printed
const ENV = { ...(require("dotenv").config({ path: ENV_FILE, processEnv: {} }).parsed || {}), ...process.env };
const RPCS = { sepolia: ENV.SEPOLIA_RPC_URL, opSepolia: ENV.OP_RPC || "https://sepolia.optimism.io", arbSepolia: ENV.ARB_RPC || "https://sepolia-rollup.arbitrum.io/rpc" };
const CHAIN = { sepolia: 11155111, opSepolia: 11155420, arbSepolia: 421614 };
const NET = process.env.NET;
const OUT = path.join(L.ROOT, "data", "testnet.jsonl");
const DEPTH = 20, WINDOW = 3600, EPOCH_LEN = 3600, POLL_MS = 250;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const now = () => Number(process.hrtime.bigint()) / 1e6;
const artifact = (n) => JSON.parse(fs.readFileSync(path.join(L.ROOT, "artifacts", "contracts", n + ".sol", (n === "PostVerifier" ? "Groth16Verifier" : n) + ".json"), "utf8"));

let provider, reader, wallet, me, nonce;
const RUN = new Date().toISOString();  // records of one run share this id; analysis keeps complete runs only
async function retry(fn, tries = 5) {  // public RPCs time out now and then; reads are safe to repeat
  for (let k = 1; ; k++) { try { return await fn(); } catch (e) { if (k >= tries) throw e; await sleep(1000 * k); } }
}

async function receiptOf(hash) {  // own polling, so inclusion time is not quantized by the library's 4 s interval
  for (;;) { const r = await retry(() => provider.send("eth_getTransactionReceipt", [hash])); if (r) return r; await sleep(POLL_MS); }
}
async function send(op, to, data, gasLimit, extra = {}, onSent = null) {
  const fee = await retry(() => provider.getFeeData());
  try { gasLimit = (await provider.estimateGas({ from: me, to, data }) * 13n) / 10n; } catch (e) { /* keep the fixed limit */ }
  const tx = { to, data, gasLimit, nonce: nonce++, chainId: CHAIN[NET], type: 2,
    maxFeePerGas: fee.maxFeePerGas * 2n, maxPriorityFeePerGas: fee.maxPriorityFeePerGas ?? 1000000n };
  const signed = await wallet.signTransaction(tx);
  const t0 = now();
  let hash;
  try { hash = await provider.send("eth_sendRawTransaction", [signed]); }
  catch (e) { if (/already known|nonce too low/i.test(String(e.message || e))) hash = ethers.keccak256(signed); else throw e; }
  const tSent = now();
  const seen = onSent ? onSent(t0) : null;
  const raw = await receiptOf(hash);
  const tRc = now();
  if (raw.status !== "0x1") throw new Error(`${op} reverted: ${hash}`);
  const big = (v) => (v == null ? null : BigInt(v).toString());
  const gasUsed = BigInt(raw.gasUsed), price = BigInt(raw.effectiveGasPrice);
  const rec = { run: RUN, net: NET, op, ...extra, txHash: hash, block: Number(raw.blockNumber), contract: raw.contractAddress || null,
    gasUsed: Number(gasUsed), effectiveGasPriceWei: price.toString(), calldataBytes: (data.length - 2) / 2, signedTxBytes: (signed.length - 2) / 2,
    gasUsedForL1: big(raw.gasUsedForL1), l1Fee: big(raw.l1Fee), l1GasUsed: big(raw.l1GasUsed), l1GasPrice: big(raw.l1GasPrice),
    l1BaseFeeScalar: big(raw.l1BaseFeeScalar), l1BlobBaseFee: big(raw.l1BlobBaseFee), l1BlobBaseFeeScalar: big(raw.l1BlobBaseFeeScalar),
    totalFeeWei: (gasUsed * price + (raw.l1Fee ? BigInt(raw.l1Fee) : 0n)).toString(),
    sendMs: tSent - t0, inclusionMs: tRc - t0, ts: new Date().toISOString() };
  if (seen) rec.visibleMs = await seen;
  fs.appendFileSync(OUT, JSON.stringify(rec) + "\n");
  console.log(`${NET} ${op}${extra.n != null ? "(" + extra.n + ")" : ""} gas=${rec.gasUsed} incl=${rec.inclusionMs.toFixed(0)}ms` + (rec.visibleMs != null ? ` visible=${rec.visibleMs.toFixed(0)}ms` : "") + (rec.l1Fee ? ` l1Fee=${rec.l1Fee}` : "") + (rec.gasUsedForL1 ? ` gasForL1=${rec.gasUsedForL1}` : ""));
  return rec;
}
async function deploy(name, args, gasLimit) {
  const a = artifact(name);
  const data = new ethers.ContractFactory(a.abi, a.bytecode).interface.encodeDeploy(args);
  const rec = await send("deploy:" + name, null, a.bytecode + data.slice(2), gasLimit);
  return new ethers.Contract(rec.contract, a.abi, provider);
}

(async () => {
  if (!RPCS[NET]) throw new Error("set NET to sepolia | opSepolia | arbSepolia (and its RPC in the .env)");
  provider = new ethers.JsonRpcProvider(RPCS[NET], CHAIN[NET], { staticNetwork: true });
  reader = new ethers.JsonRpcProvider(RPCS[NET], CHAIN[NET], { staticNetwork: true });  // the verifier's view
  wallet = new ethers.Wallet(L.privateKey(ENV), provider);
  me = await wallet.getAddress();
  nonce = await provider.getTransactionCount(me, "pending");
  const bal = await provider.getBalance(me);
  console.log(`net=${NET} chainId=${CHAIN[NET]} balance=${ethers.formatEther(bal)} ETH`);
  if (bal < ethers.parseEther("0.001")) throw new Error("balance too low; top up from a faucet");  // a full run costs < 1e-4 ETH at Oct 2026 testnet prices

  const H = await L.hasher();
  const did = await deploy("EthereumDIDRegistry", [], 1500000n);
  const reg = await deploy("IssuerRootRegistry", [await did.getAddress()], 2000000n);
  const regMap = await deploy("IssuerRootRegistryMap", [await did.getAddress()], 2000000n);
  const regAddr = await reg.getAddress(), iface = reg.interface;

  // enrollment batches; the first leaf is the member who posts later
  const today = L.dayNumber("2026-10-26");
  const schema = H(L.postHash("IC4 SocialAccountCredential v1"));
  const A = L.makeCredential(H, { secret: L.randField(), birthDate: L.dayNumber("1995-03-14"), accountCreated: L.dayNumber("2024-01-10"),
    verifiedHuman: 1, schema, salt: L.randField() });
  const tree = new L.Tree(H, DEPTH);
  const pub = async (leaves, extra) => { leaves.forEach((l) => tree.insert(l));
    return send("addLeaves", regAddr, iface.encodeFunctionData("addLeaves", [me, leaves, tree.root()]), 2500000n, extra); };
  await pub([A.leaf], { n: 1, rep: 0, phase: "first" });
  for (let k = 1; k < 16; k++) await pub([L.randField()], { n: 1, rep: k, phase: "fill" });
  for (const n of [1, 16, 128]) for (let rep = 0; rep < 3; rep++)
    await pub(Array.from({ length: n }, () => L.randField()), { n, rep, phase: "steady" });

  // revocations: time until the receipt and until an independent reader sees the new root
  for (let rep = 0; rep < 10; rep++) {
    const idx = 2 + rep;
    tree.revoke(idx);
    const newRoot = tree.root();
    const watch = (t0) => (async () => { for (;;) { if ((await retry(() => reg.connect(reader).currentRoot(me))) === newRoot) return now() - t0; await sleep(POLL_MS); } })();
    await send("revokeLeaves", regAddr, iface.encodeFunctionData("revokeLeaves", [me, [idx], newRoot]), 400000n, { n: 1, rep }, watch);
  }

  // comparison registry: one new storage slot per published root
  { const t2 = new L.Tree(H, DEPTH), mAddr = await regMap.getAddress();
    for (let rep = 0; rep < 4; rep++) { const l = L.randField(); t2.insert(l);
      await send("map.addLeaves", mAddr, regMap.interface.encodeFunctionData("addLeaves", [me, [l], t2.root()]), 2500000n, { n: 1, rep, phase: rep === 0 ? "first" : "steady" }); } }

  // on-chain posting baseline (the design verifies posts off-chain)
  const pol = { community: L.postHash("community:general"), ageCutoff: (1 << 20) - 1, seniorityCutoff: today - 30, baseLimit: 1, verifiedBonus: 4, seniorityBonus: 5, mode: 0 };
  const policyHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(Array(8).fill("uint256"),
    [schema, pol.community, pol.ageCutoff, pol.seniorityCutoff, pol.baseLimit, pol.verifiedBonus, pol.seniorityBonus, pol.mode]));
  const verifier = await deploy("PostVerifier", [], 3000000n);
  const board = await deploy("PostBoard", [regAddr, await verifier.getAddress(), me, WINDOW, EPOCH_LEN, policyHash], 1500000n);
  for (let j = 0; j < 3; j++) {
    let ts = (await provider.getBlock("latest")).timestamp;
    if (ts % EPOCH_LEN > EPOCH_LEN - 180) { await sleep((EPOCH_LEN - (ts % EPOCH_LEN) + 5) * 1000); ts = (await provider.getBlock("latest")).timestamp; }
    const epoch = Math.floor(ts / EPOCH_LEN);
    const tp = now();
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(L.postInput(tree, 0, A, pol, epoch, `testnet post ${NET} ${j}`, j), L.art("vcrln_d20").wasm, L.art("vcrln_d20").zkey);
    const proveMs = now() - tp;
    const [a, b, c, ps] = JSON.parse("[" + (await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)) + "]");
    const slot = await reg.connect(reader).currentSlot(me);
    await send("PostBoard.post", await board.getAddress(), board.interface.encodeFunctionData("post", [a, b, c, ps, slot]), 1500000n, { n: 1, rep: j, proveMs });
  }
  console.log("done", NET);
  process.exit(0);
})().catch(fail);
