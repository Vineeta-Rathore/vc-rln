// Tests of the bounds that make revocation take effect, on the local Hardhat EVM (no live transactions): a
// superseded root is refused after the window W and after a shorter grace period g chosen by a verifier, a root is
// evicted after 16 further publications even inside W, unknown roots and wrong slots are refused, only the
// issuer's current ERC-1056 owner can publish (also after a key rotation), and PostBoard refuses x = 0.
//   npx hardhat run scripts/registry_test.js        (writes data/tests_registry.json)
const fs = require("fs");
const path = require("path");
const hre = require("hardhat");
const snarkjs = require("snarkjs");
const L = require("./lib");

const { ethers } = hre;
const results = [];
const record = (name, expected, observed, pass) => {
  results.push({ name, expected, observed, pass });
  console.log(`${pass ? "PASS" : "FAIL"}  ${name}  (${observed})`);
};
// "no revert", "reverted: <exact reason>" or "other error: <reason>"
const reverts = async (p, reason) => {
  try { await (await p).wait(); return "no revert"; } catch (e) {
    const m = String(e.shortMessage || e.message || e).match(/reason string '(.*)'|reverted: "(.*)"|reverted with reason "(.*)"/);
    const got = m ? (m[1] ?? m[2] ?? m[3]) : String(e.shortMessage || e.message).slice(0, 80);
    return got === reason ? "reverted: " + reason : "other error: " + got;
  }
};
const advance = async (s) => { await hre.network.provider.send("evm_increaseTime", [s]); await hre.network.provider.send("evm_mine", []); };

(async () => {
  const [issuer, other, newOwner, poster] = await ethers.getSigners();
  const did = await (await ethers.getContractFactory("EthereumDIDRegistry")).deploy();
  const reg = await (await ethers.getContractFactory("IssuerRootRegistry")).deploy(await did.getAddress());
  const H = await L.hasher();
  const tree = new L.Tree(H, 20);
  const publish = async (signer = issuer) => { tree.insert(L.randField()); await (await reg.connect(signer).addLeaves(issuer.address, [tree.leaves.at(-1)], tree.root())).wait(); return tree.root(); };
  const W = 3600n, g = 30n;

  // R1 window: a superseded root is acceptable for W after it was superseded, then refused; a verifier that uses
  // a shorter grace period g for roots superseded by a revocation refuses it after g
  const r1 = await publish();
  tree.revoke(0);
  await (await reg.revokeLeaves(issuer.address, [0], tree.root())).wait();
  const inW = await reg.isAcceptable(issuer.address, r1, W);
  await advance(Number(g) + 1);
  const afterG = await reg.isAcceptable(issuer.address, r1, g), stillW = await reg.isAcceptable(issuer.address, r1, W);
  await advance(Number(W));
  const afterW = await reg.isAcceptable(issuer.address, r1, W);
  record("R1 superseded root accepted within W, refused after g by a short-grace verifier, refused after W",
    "true, false, true, false", `${inW}, ${afterG}, ${stillW}, ${afterW}`, inW && !afterG && stillW && !afterW);

  // The verifier's view: it audits the issuer's log (LeavesAdded, LeavesRevoked) with lib.auditRoots, which keeps for
  // each root the latest position at which the published root equals the root of the replayed tree, and applies
  // lib.rootAcceptable with the head block's time.
  // R1b grace rule for every older root: an enrollment root R_a, superseded by a further enrollment R_b, and R_b,
  // superseded by a revocation, both contain the revoked leaf. Inside W both are still in the window; under the
  // verifier rule (a root is accepted until g after the first revocation that follows it in the log) both are refused
  // after g, and the root published by the revocation is accepted.
  // R1c a later, unrelated revocation does not revive a root refused after g: its deadline is fixed by the first
  // revocation after it.
  // R1d a root published in the same block as a revocation, but before it in the log, is an older root.
  // R1e an old root republished without the events that derive it, or a root that hides leaves, is refused.
  // R1f malformed input to the root rule is refused, not accepted.
  {
    const blockTime = {};
    const timeOf = async (b) => (blockTime[b] ??= (await ethers.provider.getBlock(b)).timestamp);
    const audit = async () => {
      const logs = [...await reg.queryFilter(reg.filters.LeavesAdded(issuer.address)), ...await reg.queryFilter(reg.filters.LeavesRevoked(issuer.address))];
      const evs = [];
      for (const l of logs) evs.push({ kind: l.fragment.name === "LeavesAdded" ? "added" : "revoked", block: l.blockNumber, logIndex: l.index,
        time: await timeOf(l.blockNumber), leaves: l.args.leaves ?? [], indices: l.args.indices ?? [], root: l.args.root });
      return L.auditRoots(H, 20, evs);
    };
    const verdict = async (root) => {
      const a = await audit(), head = await ethers.provider.getBlock("latest");
      return L.rootAcceptable({ inWindow: await reg.isAcceptable(issuer.address, root, W), published: a.published.get(BigInt(root).toString()),
        revocations: a.revocations, now: head.timestamp, g: Number(g) });
    };
    const revoke = async (i) => { tree.revoke(i); return (await reg.revokeLeaves(issuer.address, [i], tree.root(), { gasLimit: 500000n })).wait(); };
    tree.insert(L.randField());
    await (await reg.addLeaves(issuer.address, [tree.leaves.at(-1)], tree.root())).wait(); const rA = tree.root();
    tree.insert(L.randField());
    await (await reg.addLeaves(issuer.address, [tree.leaves.at(-1)], tree.root())).wait(); const rB = tree.root();
    await revoke(tree.leaves.length - 2); const rR = tree.root();
    await advance(Number(g) + 1);
    const inWindowA = await reg.isAcceptable(issuer.address, rA, W);
    const a = await verdict(rA), b = await verdict(rB), r = await verdict(rR);
    record("R1b after g, every root published before the revocation is refused, though still inside W; the new root is accepted",
      "in W; false, false, true", `${inWindowA ? "in W" : "not in W"}; ${a}, ${b}, ${r}`, inWindowA && !a && !b && r);
    await revoke(tree.leaves.length - 1);
    const a2 = await verdict(rA), inW2 = await reg.isAcceptable(issuer.address, rA, W);
    record("R1c a later revocation does not revive a root refused after g", "in W; false", `${inW2 ? "in W" : "not in W"}; ${a2}`, inW2 && !a2);
    // one block: an enrollment root, then the revocation of an earlier, unrevoked leaf
    const victim = tree.insert(L.randField());
    await (await reg.addLeaves(issuer.address, [tree.leaves.at(-1)], tree.root())).wait();
    await hre.network.provider.send("evm_setAutomine", [false]);
    tree.insert(L.randField());
    const txS = await reg.addLeaves(issuer.address, [tree.leaves.at(-1)], tree.root(), { gasLimit: 500000n }), rS = tree.root();
    tree.revoke(victim);
    const txV = await reg.revokeLeaves(issuer.address, [victim], tree.root(), { gasLimit: 500000n }), rV = tree.root();
    await hre.network.provider.send("evm_mine", []);
    await hre.network.provider.send("evm_setAutomine", [true]);
    const rcS = await txS.wait(), rcV = await txV.wait();
    const sameBlock = rcS.blockNumber === rcV.blockNumber && rcS.logs[0].index < rcV.logs[0].index;
    await advance(Number(g) + 1);
    const s1 = await verdict(rS), v1 = await verdict(rV);
    record("R1d a root published in the same block as a revocation but before it is refused after g; the revocation's root is accepted",
      "same block; false, true", `${sameBlock ? "same block" : "different blocks"}; ${s1}, ${v1}`, sameBlock && !s1 && v1);
    // R1e: the issuer republishes R_a (which still holds a revoked leaf) with no new leaves; the registry makes it the
    // current root, but no event derives it there. Then a root that hides an extra leaf.
    await (await reg.addLeaves(issuer.address, [], rA)).wait();
    const revivedInW = await reg.isAcceptable(issuer.address, rA, W), revived = await verdict(rA);
    tree.insert(L.randField());
    const hidden = 777n;  // not the root of the published leaves
    await (await reg.addLeaves(issuer.address, [tree.leaves.at(-1)], hidden)).wait();
    const hiddenInW = await reg.isAcceptable(issuer.address, hidden, W), hiddenOk = await verdict(hidden);
    const mism = (await audit()).mismatched.length;
    record("R1e an old root republished without its events, and a root that does not match its leaves, are refused though the registry lists them",
      "listed; false, false; 2 mismatched", `${revivedInW && hiddenInW ? "listed" : "not listed"}; ${revived}, ${hiddenOk}; ${mism} mismatched`,
      revivedInW && hiddenInW && !revived && !hiddenOk && mism === 2);
    await publish();  // back to a root that the events derive
    const now = (await ethers.provider.getBlock("latest")).timestamp;
    const bad = [
      L.rootAcceptable({ inWindow: true, published: {}, revocations: [], now, g: 30 }),
      L.rootAcceptable({ inWindow: true, published: { block: 1, logIndex: 0 }, now, g: 30 }),
      L.rootAcceptable({ inWindow: true, published: { block: 1, logIndex: 0 }, revocations: [{ block: "9a", logIndex: 0, time: 1 }], now, g: 30 }),
      L.rootAcceptable({ inWindow: "true", published: { block: 1, logIndex: 0 }, revocations: [], now, g: 30 }),
    ];
    record("R1f malformed input to the root rule (empty position, no revocation list, a non-integer block, a non-boolean window) is refused",
      "false x4", bad.map(String).join(","), bad.every((x) => x === false));
  }

  // R2 eviction: after 16 further publications the root has left the ring, even inside W
  const old = tree.root(), oldSlot = await reg.currentSlot(issuer.address);
  for (let k = 0; k < 16; k++) await publish();
  const evicted = await reg.isAcceptable(issuer.address, old, W), evictedAt = await reg.isAcceptableAt(issuer.address, old, oldSlot, W);
  record("R2 root evicted after 16 further publications, even inside W", "false, false", `${evicted}, ${evictedAt}`, !evicted && !evictedAt);

  // R3 unknown roots and wrong slots are refused; the current root is accepted at its slot
  const cur = await reg.currentRoot(issuer.address), curSlot = await reg.currentSlot(issuer.address);
  const unknown = await reg.isAcceptable(issuer.address, 12345n, W);
  const wrongSlot = await reg.isAcceptableAt(issuer.address, cur, (curSlot + 1n) % 16n, W);
  const right = await reg.isAcceptableAt(issuer.address, cur, curSlot, W);
  record("R3 unknown root and wrong slot refused, current root accepted at its slot", "false, false, true", `${unknown}, ${wrongSlot}, ${right}`, !unknown && !wrongSlot && right);

  // R4 publishing right: only the current ERC-1056 owner of the issuer's identity; after a rotation the old key is
  // refused and the new one accepted; revoking a leaf that does not exist is refused
  tree.insert(L.randField());
  const notOwner = await reverts(reg.connect(other).addLeaves(issuer.address, [tree.leaves.at(-1)], tree.root()), "not the issuer's DID owner");
  await (await did.connect(issuer).changeOwner(issuer.address, newOwner.address)).wait();
  const oldKey = await reverts(reg.connect(issuer).addLeaves(issuer.address, [tree.leaves.at(-1)], tree.root()), "not the issuer's DID owner");
  const newKey = await reverts(reg.connect(newOwner).addLeaves(issuer.address, [tree.leaves.at(-1)], tree.root()), "");
  const noLeaf = await reverts(reg.connect(newOwner).revokeLeaves(issuer.address, [10_000], tree.root()), "no such leaf");
  record("R4 non-owner refused; after rotation the old key is refused and the new key publishes", "refused, refused, published",
    `${notOwner}, ${oldKey}, ${newKey}`, notOwner === "reverted: not the issuer's DID owner" && oldKey === notOwner && newKey === "no revert");
  record("R4 revoking a leaf that does not exist is refused", "reverted: no such leaf", noLeaf, noLeaf === "reverted: no such leaf");

  // R5 PostBoard refuses x = 0 (with x = 0 the share y equals the secret, and 0 marks an unused nullifier)
  const verifier = await (await ethers.getContractFactory("Groth16Verifier")).deploy();
  const ptree = new L.Tree(H, 20), today = L.dayNumber("2026-10-26"), schema = H(L.postHash("IC4 SocialAccountCredential v1"));
  const pol = { community: L.postHash("community:general"), ageCutoff: L.NO_AGE_GATE, seniorityCutoff: today - 30, baseLimit: 1, verifiedBonus: 4, seniorityBonus: 5, mode: 0 };
  const A = L.makeCredential(H, { secret: L.randField(), birthDate: L.dayNumber("1995-03-14"), accountCreated: L.dayNumber("2024-01-10"), verifiedHuman: 1, schema, salt: L.randField() });
  const iA = ptree.insert(A.leaf);
  await (await reg.connect(poster).addLeaves(poster.address, ptree.leaves, ptree.root())).wait();
  const policyHash = ethers.keccak256(ethers.AbiCoder.defaultAbiCoder().encode(Array(8).fill("uint256"),
    [schema, pol.community, pol.ageCutoff, pol.seniorityCutoff, pol.baseLimit, pol.verifiedBonus, pol.seniorityBonus, pol.mode]));
  const EPOCH_LEN = 3600;
  const board = await (await ethers.getContractFactory("PostBoard")).deploy(await reg.getAddress(), await verifier.getAddress(), poster.address, W, EPOCH_LEN, policyHash);
  const T = (await ethers.provider.getBlock("latest")).timestamp + 10, epoch = Math.floor(T / EPOCH_LEN);
  const input = { ...L.postInput(ptree, iA, A, pol, epoch, "zero", 0), x: 0 };
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(input, L.art("vcrln_d20").wasm, L.art("vcrln_d20").zkey);
  const validProof = await snarkjs.groth16.verify(L.art("vcrln_d20").vkey, publicSignals, proof);
  const [a, b, c, pub] = JSON.parse("[" + (await snarkjs.groth16.exportSolidityCallData(proof, publicSignals)) + "]");
  await hre.network.provider.send("evm_setNextBlockTimestamp", [T]);
  const zero = await reverts(board.connect(poster).post(a, b, c, pub, await reg.currentSlot(poster.address)), "x");
  record("R5 a valid proof with x = 0 is refused by PostBoard", "valid proof; reverted: x", `${validProof ? "valid proof" : "invalid proof"}; ${zero}`, validProof && zero === "reverted: x");

  const passed = results.filter((r) => r.pass).length;
  console.log(`\n${passed}/${results.length} registry checks passed`);
  fs.writeFileSync(path.join(L.ROOT, "data", "tests_registry.json"), JSON.stringify({ network: "hardhat", hardfork: hre.network.config.hardfork || null,
    date: new Date().toISOString(), passed, total: results.length, results }, null, 1));
  process.exit(passed === results.length ? 0 : 1);
})().catch((e) => { console.error("registry test aborted:", e); process.exit(1); });
