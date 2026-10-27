// Proving time in the installed Chrome (headless) on the same laptop: the closest stand-in for a user's device.
// A local server serves snarkjs.min.js, the circuit wasm/zkey and pre-generated inputs; the page loads wasm and
// zkey into memory once (fetch time excluded), runs WARM warm-up + RUNS timed fullProve calls, and verifies the
// last proof. Two passes over the configurations in opposite order, a fresh browser page per configuration.
//   PUPPETEER_CORE=<path to puppeteer-core> CHROME=<path to chrome.exe> node scripts/bench_browser.js
// fullProve compiles the witness program on every call, as a page that uses snarkjs does; the first call of each
// page is also kept, as the cold proof. Appends data/bench_browser_runs.jsonl, data/bench_browser.jsonl and
// data/bench_browser_pair.jsonl.
const fs = require("fs");
const http = require("http");
const os = require("os");
const path = require("path");
const L = require("./lib");

const puppeteer = require(process.env.PUPPETEER_CORE || "puppeteer-core");
const CHROME = process.env.CHROME || "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
const RUNS = Number(process.env.RUNS || 20), WARM = Number(process.env.WARM || 10);
const SESSION = process.env.SESSION || new Date().toISOString();
const CONFIGS = (process.env.CONFIGS || "vcrln_d20 rln2_d20").split(" ");
const TMP = path.join(L.ROOT, "build", "browser");
fs.mkdirSync(TMP, { recursive: true });

const PAIRS = Number(process.env.BROWSER_PAIRS || 15), PAGES = Number(process.env.BROWSER_PAGES || 4);  // alternating pairs per page
async function makeInputs(name, n) {  // the Node benchmark's workload (lib.benchWorkload), built before any timing
  const make = L.benchWorkload(await L.hasher(), name);
  return JSON.stringify(Array.from({ length: n }, (_, k) => make(k)), (k, v) => (typeof v === "bigint" ? v.toString() : v));
}

const PAGE = `<!doctype html><meta charset="utf-8"><script src="/snarkjs.min.js"></script><body>bench</body>`;

function serve() {
  const files = {
    "/": { type: "text/html", body: () => PAGE },
    "/snarkjs.min.js": { type: "application/javascript", file: path.join(L.ROOT, "node_modules", "snarkjs", "build", "snarkjs.min.js") },
  };
  const server = http.createServer((req, res) => {
    const u = decodeURIComponent(req.url.split("?")[0]);
    let f = files[u];
    if (!f && /^\/build\/[a-z0-9_]+\/(c_js\/c\.wasm|c\.zkey|vkey\.json)$/.test(u)) f = { type: "application/octet-stream", file: path.join(L.ROOT, u) };
    if (!f && /^\/inputs\/[a-z0-9_]+\.json$/.test(u)) f = { type: "application/json", file: path.join(TMP, path.basename(u)) };
    if (!f) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { "Content-Type": f.type, "Cache-Control": "no-store" });
    res.end(f.body ? f.body() : fs.readFileSync(f.file));
  });
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server)));
}

(async () => {
  for (const name of CONFIGS) fs.writeFileSync(path.join(TMP, name + ".json"), await makeInputs(name, Math.max(WARM + RUNS, WARM + PAIRS)));
  const server = await serve();
  const base = `http://127.0.0.1:${server.address().port}`;
  const browser = await puppeteer.launch({ executablePath: CHROME, headless: true,
    args: ["--disable-background-timer-throttling", "--disable-renderer-backgrounding", "--disable-backgrounding-occluded-windows"] });
  const version = await browser.version();
  const passes = [["forward", CONFIGS], ["reverse", [...CONFIGS].reverse()]];
  for (const [pass, order] of passes) {
    for (const name of order) {
      const ctx = await browser.createBrowserContext();
      const page = await ctx.newPage();
      await page.goto(base + "/", { waitUntil: "load" });
      const r = await page.evaluate(async (name, warm, runs) => {
        const get = async (u) => new Uint8Array(await (await fetch(u)).arrayBuffer());
        const wasm = await get(`/build/${name}/c_js/c.wasm`), zkey = await get(`/build/${name}/c.zkey`);
        const vkey = await (await fetch(`/build/${name}/vkey.json`)).json();
        const inputs = await (await fetch(`/inputs/${name}.json`)).json();
        const times = [];
        let last, cold;
        for (let k = 0; k < warm + runs; k++) {
          const t0 = performance.now();
          last = await snarkjs.groth16.fullProve(inputs[k], { type: "mem", data: wasm }, { type: "mem", data: zkey });
          const dt = performance.now() - t0;
          if (k === 0) cold = dt;
          if (k >= warm) times.push(dt);
        }
        const ok = await snarkjs.groth16.verify(vkey, last.publicSignals, last.proof);
        return { times, cold, ok, threads: navigator.hardwareConcurrency, ua: navigator.userAgent };
      }, name, WARM, RUNS);
      await ctx.close();
      if (!r.ok) throw new Error(name + ": proof made in the browser did not verify");
      const runLog = (rec) => fs.appendFileSync(path.join(L.ROOT, "data", "bench_browser_runs.jsonl"), JSON.stringify({ session: SESSION, name, pass, ...rec }) + "\n");
      runLog({ cold: true, run: -1, totalMs: r.cold });
      r.times.forEach((t, i) => runLog({ cold: false, run: i, totalMs: t }));
      const m = r.times.reduce((a, b) => a + b, 0) / r.times.length;
      const sd = Math.sqrt(r.times.reduce((a, b) => a + (b - m) ** 2, 0) / (r.times.length - 1));
      const sorted = [...r.times].sort((a, b) => a - b), p95 = sorted[Math.ceil(0.95 * sorted.length) - 1];
      fs.appendFileSync(path.join(L.ROOT, "data", "bench_browser.jsonl"), JSON.stringify({ session: SESSION, name, pass, warm: WARM, coldMs: r.cold, runs: RUNS, meanMs: m, sdMs: sd, p95Ms: p95,
        verified: r.ok, browser: version, threads: r.threads, cpu: os.cpus()[0].model.trim(), ts: new Date().toISOString() }) + "\n");
      console.log(`${name} [${pass}] browser prove ${m.toFixed(0)} +- ${sd.toFixed(0)} ms (p95 ${p95.toFixed(0)}), verified=${r.ok}, threads=${r.threads}`);
    }
  }
  // paired: both circuits in one page, alternating, order inside each pair alternating too; PAGES fresh pages, so
  // the page can be the unit of the interval
  for (let pg = 0; PAIRS > 0 && CONFIGS.length === 2 && pg < PAGES; pg++) {
    const ctx = await browser.createBrowserContext();
    const page = await ctx.newPage();
    await page.goto(base + "/", { waitUntil: "load" });
    const r = await page.evaluate(async (names, warm, pairs) => {
      const get = async (u) => new Uint8Array(await (await fetch(u)).arrayBuffer());
      const c = {};
      for (const n of names) c[n] = { wasm: await get(`/build/${n}/c_js/c.wasm`), zkey: await get(`/build/${n}/c.zkey`),
        vkey: await (await fetch(`/build/${n}/vkey.json`)).json(), inputs: await (await fetch(`/inputs/${n}.json`)).json() };
      const out = [];
      let ok = true;
      for (let k = 0; k < warm + pairs; k++) {
        const order = k % 2 ? [names[1], names[0]] : [names[0], names[1]], rec = { pair: k - warm, first: order[0] };
        for (const n of order) {
          const t0 = performance.now();
          const p = await snarkjs.groth16.fullProve(c[n].inputs[k], { type: "mem", data: c[n].wasm }, { type: "mem", data: c[n].zkey });
          rec[n] = performance.now() - t0;
          if (k === warm + pairs - 1) ok = ok && (await snarkjs.groth16.verify(c[n].vkey, p.publicSignals, p.proof));
        }
        if (k >= warm) out.push(rec);
      }
      return { out, ok };
    }, CONFIGS, WARM, PAIRS);
    await ctx.close();
    if (!r.ok) throw new Error("paired browser proofs did not verify");
    for (const rec of r.out) fs.appendFileSync(path.join(L.ROOT, "data", "bench_browser_pair.jsonl"), JSON.stringify({ session: SESSION, browser: version, page: pg, ...rec, ts: new Date().toISOString() }) + "\n");
    const d = r.out.map((x) => x[CONFIGS[0]] - x[CONFIGS[1]]), m = d.reduce((a, b) => a + b, 0) / d.length;
    console.log(`browser paired, page ${pg}: ${d.length} pairs, ${CONFIGS[0]} - ${CONFIGS[1]} = ${m.toFixed(1)} ms`);
  }
  await browser.close();
  server.close();
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
