// Gas on the Hardhat EVM (Osaka rules): issuer root publication (first publication, ring fill, steady state
// once the 16-root ring has wrapped) for batches of 1, 16 and 128 leaves; revocation; DID key rotation; the
// per-root comparison registry; and the on-chain posting baseline with a real depth-20 proof. Leaves and proofs are
// random, so a rerun can differ by 12 gas per zero calldata byte (tens of gas per transaction).
//   npx hardhat run scripts/gas_local.js        (writes data/gas_local.jsonl)
const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const snarkjs = require("snarkjs");
const L = require("./lib");

const OUT = path.join(L.ROOT, "data", "gas_local.jsonl");
const DEPTH = 20, WINDOW = 3600, EPOCH_LEN = 3600, HISTORY = 16;

(async () => {
  const { ethers } = hre;
  fs.writeFileSync(OUT, "");
  const hardfork = hre.network.config.hardfork;
  const signers = await ethers.getSigners();
  const H = await L.hasher();
  async function rec(op, n, txOrRc, extra = {}) {
    const rc = txOrRc.wait ? await txOrRc.wait() : txOrRc;
    const tx = await ethers.provider.getTransaction(rc.hash);
    const r = { op, n, gasUsed: Number(rc.gasUsed), calldataBytes: (tx.data.length - 2) / 2, hardfork, ...extra };
    fs.appendFileSync(OUT, JSON.stringify(r) + "\n");
    console.log(`${op} n=${n} gas=${r.gasUsed} calldata=${r.calldataBytes}B ${extra.phase || ""}`);
    return r;
  }
  const deploy = async (name, args = [], label = name) => {
    const c = await (await ethers.getContractFactory(name)).deploy(...args);
    await rec("deploy:" + label, 0, await c.deploymentTransaction().wait());
    return c;
  };
  const publish = async (reg, issuer, tree, n, phase, op = "addLeaves") => {
    const leaves = Array.from({ length: n }, () => L.randField());
    leaves.forEach((l) => tree.insert(l));
    const tx = await reg.connect(issuer).addLeaves(issuer.address, leaves, tree.root());
    return phase ? rec(op, n, tx, { phase }) : tx.wait();
  };

  const did = await deploy("EthereumDIDRegistry");
  const reg = await deploy("IssuerRootRegistry", [await did.getAddress()]);
  const regMap = await deploy("IssuerRootRegistryMap", [await did.getAddress()]);

  // ring registry: first publication of size n, fill the ring with single-leaf publications, then steady state
  let s = 3;
  for (const n of [1, 16, 128]) {
    const issuer = signers[s++], tree = new L.Tree(H, DEPTH);
    await publish(reg, issuer, tree, n, "first");
    for (let k = 1; k < HISTORY; k++) await publish(reg, issuer, tree, 1, n === 1 ? "fill" : null);
    for (let k = 0; k < 3; k++) await publish(reg, issuer, tree, n, "steady");
    if (n === 128) {  // the tree now holds 527 leaves; the three revocation batches use disjoint index ranges
      for (const [m, offset] of [[1, 10], [16, 20], [128, 100]]) {
        const idx = Array.from({ length: m }, (_, i) => offset + i);
        idx.forEach((i) => tree.revoke(i));
        await rec("revokeLeaves", m, await reg.connect(issuer).revokeLeaves(issuer.address, idx, tree.root()), { phase: "steady" });
      }
    }
  }
  // comparison design: one new storage slot per published root
  {
    const issuer = signers[s++], tree = new L.Tree(H, DEPTH);
    await publish(regMap, issuer, tree, 1, "first", "map.addLeaves");
    for (let k = 0; k < 3; k++) await publish(regMap, issuer, tree, 1, "steady", "map.addLeaves");
  }

  // DID key rotation moves the publishing right: old key rejected, new owner accepted
  {
    const issuer = signers[1], newOwner = signers[2], tree = new L.Tree(H, DEPTH);
    await publish(reg, issuer, tree, 1, null);
    await rec("ERC1056.changeOwner", 0, await did.connect(issuer).changeOwner(issuer.address, newOwner.address));
    tree.insert(L.randField());
    let oldKeyRejected = false;
    try { await (await reg.connect(issuer).addLeaves(issuer.address, [tree.leaves[1]], tree.root())).wait(); } catch (e) { oldKeyRejected = true; }
    await rec("addLeaves.afterRotation", 1, await reg.connect(newOwner).addLeaves(issuer.address, [tree.leaves[1]], tree.root()), { phase: "second publication", oldKeyRejected });
  }

  // on-chain posting baseline: one community verified by the generated Groth16 verifier
  const verifier = await deploy("Groth16Verifier", [], "PostVerifier(d20)");
  const postIssuer = signers[0], ptree = new L.Tree(H, DEPTH);
  const today = L.dayNumber("2026-10-26");
  const schema = H(L.postHash("IC4 SocialAccountCredential v1"));
  const pol = { community: L.postHash("community:general"), ageCutoff: (1 << 20) - 1, seniorityCutoff: today - 30,
    baseLimit: 1, verifiedBonus: 4, seniorityBonus: 5, mode: 0 };
  const A = L.makeCredential(H, { secret: L.randField(), birthDate: L.dayNumber("1995-03-14"),
    accountCreated: L.dayNumber("2024-01-10"), verifiedHuman: 1, schema, salt: L.randField() });
  const iA = ptree.insert(A.leaf);
  for (let k = 0; k < 7; k++) ptree.insert(L.randField());
  await (await reg.connect(postIssuer).addLeaves(postIssuer.address, ptree.leaves, ptree.root())).wait();
  const abi = ethers.AbiCoder.defaultAbiCoder();
  const policyHash = ethers.keccak256(abi.encode(Array(8).fill("uint256"),
    [schema, pol.community, pol.ageCutoff, pol.seniorityCutoff, pol.baseLimit, pol.verifiedBonus, pol.seniorityBonus, pol.mode]));
  const board = await deploy("PostBoard", [await reg.getAddress(), await verifier.getAddress(), postIssuer.address, WINDOW, EPOCH_LEN, policyHash]);
  const slot = await reg.currentSlot(postIssuer.address);
  const T = (await ethers.provider.getBlock("latest")).timestamp + 10;
  const epoch = Math.floor(T / EPOCH_LEN);
  for (const j of [0, 1]) {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(L.postInput(ptree, iA, A, pol, epoch, "on-chain post " + j, j), L.art("vcrln_d20").wasm, L.art("vcrln_d20").zkey);
    const [a, b, c, pub] = JSON.parse("[" + (await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)) + "]");
    const raw = Number(await verifier.verifyProof.estimateGas(a, b, c, pub));
    await hre.network.provider.send("evm_setNextBlockTimestamp", [T + j]);
    await rec("PostBoard.post", 1, await board.connect(signers[5]).post(a, b, c, pub, slot), { phase: j === 0 ? "first" : "second", rawVerifierEstimate: raw });
    if (j === 1) {  // a reused nullifier is rejected before verification
      let reverted = false;
      try { await (await board.connect(signers[5]).post(a, b, c, pub, slot)).wait(); } catch (e) { reverted = /nullifier used/.test(String(e)); }
      fs.appendFileSync(OUT, JSON.stringify({ op: "PostBoard.post.replay", n: 1, reverted, hardfork }) + "\n");
      console.log("replay rejected:", reverted);
    }
  }
  console.log("hardfork:", hardfork);
  process.exit(0);  // snarkjs keeps worker threads alive
})().catch((e) => { console.error(e); process.exit(1); });
