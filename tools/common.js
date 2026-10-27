// Helpers shared by the checking scripts: the BN254 field, Poseidon (circomlibjs), the issuer's Merkle tree and the
// RLN secret recovery, written as in the measurement code. No key, no transaction.
const { buildPoseidon } = require("circomlibjs");
const { keccak256, toUtf8Bytes, JsonRpcProvider } = require("ethers");

const P = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const mod = (a) => ((a % P) + P) % P;
function inv(a) {
  let r = 1n, b = mod(a), e = P - 2n;
  while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; }
  return r;
}
const postHash = (text) => mod(BigInt(keccak256(toUtf8Bytes(text))));

async function hasher() {
  const p = await buildPoseidon();
  return (...xs) => p.F.toObject(p(xs.map((v) => BigInt(v))));
}

// binary Poseidon tree with zero leaves; a revoked leaf is set to 0
class Tree {
  constructor(H, depth) {
    this.H = H; this.depth = depth; this.leaves = []; this.zeros = [0n];
    for (let i = 0; i < depth; i++) this.zeros.push(H(this.zeros[i], this.zeros[i]));
  }
  insert(leaf) { this.leaves.push(BigInt(leaf)); }
  revoke(i) { this.leaves[i] = 0n; }
  root() {
    let cur = this.leaves.slice();
    for (let l = 0; l < this.depth; l++) {
      const next = [];
      for (let i = 0; i < Math.ceil(cur.length / 2); i++) next.push(this.H(cur[2 * i] ?? this.zeros[l], cur[2 * i + 1] ?? this.zeros[l]));
      cur = next;
    }
    return cur[0] ?? this.zeros[this.depth];
  }
}

function recoverSecret(x1, y1, x2, y2) {
  const a1 = mod((mod(y2) - mod(y1)) * inv(mod(x2) - mod(x1)));
  return mod(y1 - a1 * x1);
}

// public endpoints that serve the old logs rebuild_tree.js needs; override with SEPOLIA_RPC, OP_RPC, ARB_RPC
const RPC = { sepolia: process.env.SEPOLIA_RPC || "https://sepolia.gateway.tenderly.co",
  opSepolia: process.env.OP_RPC || "https://sepolia.optimism.io",
  arbSepolia: process.env.ARB_RPC || "https://sepolia-rollup.arbitrum.io/rpc" };
const CHAIN = { sepolia: 11155111, opSepolia: 11155420, arbSepolia: 421614 };
const provider = (net) => new JsonRpcProvider(RPC[net], CHAIN[net], { staticNetwork: true });
const EXPLORER = { sepolia: "https://sepolia.etherscan.io/tx/", opSepolia: "https://sepolia-optimism.etherscan.io/tx/",
  arbSepolia: "https://sepolia.arbiscan.io/tx/" };

// A public endpoint may rate-limit, drop a connection or stall: each request gets a time limit and is retried with
// growing pauses; the last error is thrown so that the caller can report the endpoint, not a wrong result.
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function retry(fn, tries = 6, limitMs = 30000) {
  let last;
  for (let k = 0; k < tries; k++) {
    let timer;
    try {
      return await Promise.race([fn(), new Promise((_, no) => { timer = setTimeout(() => no(new Error("request timed out")), limitMs); })]);
    } catch (e) {
      last = e;
      await sleep(2000 * 2 ** k);
    } finally {
      clearTimeout(timer);
    }
  }
  throw last;
}

module.exports = { P, mod, postHash, hasher, Tree, recoverSecret, provider, EXPLORER, retry, sleep };
