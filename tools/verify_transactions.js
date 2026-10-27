// Fetches the receipt of every transaction in data/transactions.csv from a public endpoint and checks that it
// succeeded and used the gas we report. Read-only. Receipts that the endpoint does not return after several
// attempts are reported separately from mismatches; rerun, or set SEPOLIA_RPC, OP_RPC or ARB_RPC, to check them.
//   node tools/verify_transactions.js
const fs = require("fs");
const path = require("path");
const { provider, EXPLORER, retry, sleep } = require("./common");

const rows = fs.readFileSync(path.join(__dirname, "..", "data", "transactions.csv"), "utf8").trim().split(/\r?\n/);
const head = rows.shift().split(",");
const txs = rows.map((l) => Object.fromEntries(l.split(",").map((v, i) => [head[i], v])));

(async () => {
  const prov = {}, tally = {};
  let bad = 0, unreached = 0;
  for (const t of txs) {
    prov[t.network] ??= provider(t.network);
    const key = `${t.network} / ${t.source}`;
    tally[key] ??= { ok: 0, mismatch: 0, unreached: 0 };
    let r;
    try {
      // a load-balanced public endpoint can answer "not found" from a node that lacks the block: retry that too
      r = await retry(async () => {
        const x = await prov[t.network].getTransactionReceipt(t.txHash);
        if (!x) throw new Error("receipt not returned");
        return x;
      });
    } catch (e) {
      tally[key].unreached++; unreached++;
      console.log(`UNREACHED ${t.operation} ${EXPLORER[t.network]}${t.txHash}: endpoint error`);
      continue;
    }
    if (r && r.status === 1 && r.gasUsed.toString() === t.gasUsed) tally[key].ok++;
    else {
      tally[key].mismatch++; bad++;
      console.log(`MISMATCH ${t.operation} ${EXPLORER[t.network]}${t.txHash}: reported ${t.gasUsed}, chain ${r ? r.gasUsed + " status " + r.status : "no receipt"}`);
    }
    await sleep(100);  // stay under public rate limits
  }
  console.table(tally);
  if (bad) console.log(`${bad} of ${txs.length} transactions did not match`);
  if (unreached) console.log(`${unreached} of ${txs.length} receipts could not be fetched; rerun or use another endpoint`);
  if (!bad && !unreached) console.log(`all ${txs.length} transactions found, successful, with the reported gas`);
  process.exit(bad || unreached ? 1 : 0);
})();
