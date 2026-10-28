"""Every number the IC4 paper cites, computed from the raw data files, plus a few related figures it does not cite
(e.g. unpaired overheads from the depth sweep and from separate Chrome pages). Prints a report and writes
data/paper_numbers.json; tables for the manuscript are written to data/tables/*.csv. The benchmark sessions it cites
are named in analysis/sessions.json; without that file it takes the latest complete session of each benchmark.
Run after analysis/agility.py (see analysis/run_all.sh).
   python analysis/paper_numbers.py
"""
import csv
import json
import math
import re
import statistics as st
import sys
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", newline="\n")  # LF on every platform (data/SHA256SUMS)
sys.path.insert(0, str(Path(__file__).resolve().parent))
ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"
TAB = DATA / "tables"
TAB.mkdir(exist_ok=True)
N = {}  # name -> value, everything the paper cites
SESS_FILE = Path(__file__).resolve().parent / "sessions.json"
SESS = json.loads(SESS_FILE.read_text(encoding="utf-8")) if SESS_FILE.exists() else {}


# sessions that run_cpu_suite.sh declared invalid (power left mains during a step) are never cited
INVALID = {l.split()[0] for l in (DATA / "invalid_sessions.txt").read_text(encoding="utf-8").splitlines() if l.strip()} \
    if (DATA / "invalid_sessions.txt").exists() else set()


def pick(rows, key, complete):
    """The cited session of one benchmark: the one named in sessions.json, else the latest complete suite session
    (an ISO timestamp id, never a smoke or diagnostic run), never one declared invalid."""
    ids = list(dict.fromkeys(r["session"] for r in rows if r.get("session")))
    if key in SESS:
        sid = SESS[key]
        assert sid not in INVALID, f"session {sid} of {key} was declared invalid"
        assert complete([r for r in rows if r.get("session") == sid]), f"session {sid} of {key} is incomplete"
        return sid
    for sid in reversed(ids):
        if re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", sid) and sid not in INVALID and complete([r for r in rows if r.get("session") == sid]):
            return sid
    return None


T95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776, 5: 2.571, 6: 2.447, 7: 2.365, 8: 2.306, 9: 2.262, 10: 2.228, 11: 2.201, 12: 2.179,
       13: 2.160, 14: 2.145, 15: 2.131, 16: 2.120, 17: 2.110, 18: 2.101, 19: 2.093, 20: 2.086, 25: 2.060, 30: 2.042}


def t95(df):  # two-sided 95% Student t quantile; between table rows the next smaller df is used (conservative)
    return T95[max(k for k in T95 if k <= df)] if df >= 1 else float("nan")


def jl(name):
    p = DATA / name
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


def q(xs, p):
    s = sorted(xs)
    h = (len(s) - 1) * p
    lo = int(h)
    return s[lo] + (s[min(lo + 1, len(s) - 1)] - s[lo]) * (h - lo)


def write_csv(name, header, rows):
    with open(TAB / name, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


# ---- circuit size and timing (Table II) -----------------------------------------------------------
info = {p.parent.name: json.loads(p.read_text(encoding="utf-8")) for p in (ROOT / "build").glob("*/info.json")}
# sweep: one bench.sh session; warm runs reuse the compiled witness calculator and the in-memory zkey
order = ["vcrln_d10", "vcrln_d16", "vcrln_d20", "vcrln_d24", "vcrln_d32", "rln2_d20"]
_br = [r for r in jl("bench_runs.jsonl") if r.get("session") and r.get("pass") in ("forward", "reverse")]
_sweep_ok = lambda rs: all(sum(1 for r in rs if r["name"] == n and r["pass"] == p and not r.get("cold")) >= 30
                           for n in order for p in ("forward", "reverse"))
SESSION = pick(_br, "sweep", _sweep_ok)
N["bench.session"] = SESSION
runs = defaultdict(list)
for r in _br:
    if r["session"] == SESSION and not r.get("cold"):
        runs[r["name"]].append(r)
summ = defaultdict(list)
for r in jl("bench.jsonl"):
    if r.get("session") == SESSION:
        summ[r["name"]].append(r)
if summ:
    s0 = next(iter(summ.values()))[0]
    N["bench.setup"] = {"warm": s0.get("warm"), "runs": s0.get("runs"), "node": s0.get("node"), "snarkjs": s0.get("snarkjs"),
                        "cpu": s0.get("cpu"), "cores": s0.get("cores")}
# cold first proofs: fresh processes, files from disk (bench_cold.js)
_bc = jl("bench_cold.jsonl")
CS = pick(_bc, "cold", lambda rs: all(sum(1 for r in rs if r["name"] == n) >= 10 for n in ("vcrln_d20", "rln2_d20")))
for name in ("vcrln_d20", "rln2_d20"):
    xs = [r["totalMs"] for r in _bc if r.get("session") == CS and r["name"] == name]
    if xs:
        N[f"cold.{name}"] = {"n": len(xs), "mean": st.mean(xs), "median": st.median(xs), "min": min(xs), "max": max(xs)}
if CS:
    r0 = next(r for r in _bc if r.get("session") == CS and r["name"] == "vcrln_d20")
    N["cold.downloadMB"] = (r0["wasmBytes"] + r0["zkeyBytes"]) / 1e6
N["cold.session"] = CS
# tree cost at the modelled size (bench_tree.js)
_bt = jl("bench_tree.jsonl")
TS = pick(_bt, "tree", lambda rs: any(r["leaves"] >= 100000 for r in rs))
N["tree"] = next((r for r in _bt if r.get("session") == TS and r["leaves"] >= 100000), None)
rows = []
for name in order:
    if name not in info:
        continue
    tot = [r["totalMs"] for r in runs.get(name, [])]
    wit = [r["witnessMs"] for r in runs.get(name, [])]
    ver = [s["verify"]["mean"] for s in summ.get(name, [])]
    row = {"name": name, "constraints": info[name]["constraints"], "zkeyMB": info[name]["zkeyBytes"] / 2**20}
    if tot:
        row.update(n=len(tot), mean=st.mean(tot), sd=st.stdev(tot), p50=q(tot, .5), p95=q(tot, .95),
                   witness=st.mean(wit), verify=st.mean(ver),
                   passes={p: st.mean([r["totalMs"] for r in runs[name] if r["pass"] == p]) for p in ("forward", "reverse")})
    rows.append(row)
    N[f"circuit.{name}"] = row
if "vcrln_d20" in info and "rln2_d20" in info:
    d = info["vcrln_d20"]["constraints"] - info["rln2_d20"]["constraints"]
    N["overhead.constraints"] = d
    N["overhead.constraintsPct"] = 100 * d / info["rln2_d20"]["constraints"]
    N["perLevel.constraints"] = (info["vcrln_d32"]["constraints"] - info["vcrln_d10"]["constraints"]) / 22
    if runs.get("vcrln_d20") and runs.get("rln2_d20"):
        A_, B_ = [r["totalMs"] for r in runs["vcrln_d20"]], [r["totalMs"] for r in runs["rln2_d20"]]
        a, b = st.mean(A_), st.mean(B_)
        se = (st.variance(A_) / len(A_) + st.variance(B_) / len(B_)) ** 0.5  # Welch; runs are not fully independent
        N["overhead.proveMs"] = a - b
        N["overhead.provePct"] = 100 * (a - b) / b
        N["overhead.proveMsCI95"] = [a - b - 1.96 * se, a - b + 1.96 * se]
        N["overhead.passes"] = {p: st.mean(r["totalMs"] for r in runs["vcrln_d20"] if r["pass"] == p)
                                - st.mean(r["totalMs"] for r in runs["rln2_d20"] if r["pass"] == p) for p in ("forward", "reverse")}
        for part in ("witnessMs", "proveMs"):
            N[f"overhead.part.{part}"] = st.mean(r[part] for r in runs["vcrln_d20"]) - st.mean(r[part] for r in runs["rln2_d20"])
# paired benchmark (bench_pair.js): both depth-20 circuits alternating in one process, inputs built before timing.
# The process is the unit: one mean difference per process, a t interval across processes; the pooled per-pair
# interval and the order effect (difference when our circuit runs first vs second) are reported alongside.
_pr = [r for r in jl("bench_pair.jsonl") if r.get("proc")]
_procs = lambda rs: {p: [r for r in rs if r["proc"] == p] for p in sorted({r["proc"] for r in rs})}
# complete: at least two processes, all with the same number (at least 100) of pairs
PS = pick(_pr, "pair", lambda rs: len(_procs(rs)) >= 2 and len({len(v) for v in _procs(rs).values()}) == 1
          and min(len(v) for v in _procs(rs).values()) >= 100)
def pair_stats(PS):
    pr = [r for r in _pr if r["session"] == PS]
    procs = _procs(pr)
    pair = {"session": PS, "pairs": len(pr), "processes": len(procs), "pairsPerProcess": min(len(v) for v in procs.values())}
    for part in ("witnessMs", "proveMs", "totalMs"):
        d = [r["vcrln_d20"][part] - r["rln2_d20"][part] for r in pr]
        per = [st.mean(r["vcrln_d20"][part] - r["rln2_d20"][part] for r in v) for v in procs.values()]
        b = st.mean(r["rln2_d20"][part] for r in pr)
        half = t95(len(per) - 1) * st.stdev(per) / len(per) ** 0.5 if len(per) > 1 else float("nan")
        pair[part] = {"ours": st.mean(r["vcrln_d20"][part] for r in pr), "rln2": b, "diff": st.mean(d), "pct": 100 * st.mean(d) / b,
                      "perProcess": per, "ci95Process": [st.mean(per) - half, st.mean(per) + half],
                      "ci95Pairs": [st.mean(d) - 1.96 * st.stdev(d) / len(d) ** 0.5, st.mean(d) + 1.96 * st.stdev(d) / len(d) ** 0.5]}
    first = [r["vcrln_d20"]["totalMs"] - r["rln2_d20"]["totalMs"] for r in pr if r["first"] == "vcrln_d20"]
    second = [r["vcrln_d20"]["totalMs"] - r["rln2_d20"]["totalMs"] for r in pr if r["first"] == "rln2_d20"]
    pair["orderEffect"] = {"oursFirst": st.mean(first), "oursSecond": st.mean(second)}
    # stationarity: change of the RLN v2 proof time between the first and the last quarter of each process
    pair["driftPct"] = {pid: 100 * (st.mean(r["rln2_d20"]["totalMs"] for r in v[-len(v) // 4:])
                                    / st.mean(r["rln2_d20"]["totalMs"] for r in v[:len(v) // 4]) - 1) for pid, v in procs.items()}
    pair["pctPerProcess"] = {pid: 100 * st.mean(r["vcrln_d20"]["totalMs"] - r["rln2_d20"]["totalMs"] for r in v)
                             / st.mean(r["rln2_d20"]["totalMs"] for r in v) for pid, v in procs.items()}
    _pp = list(pair["pctPerProcess"].values())
    _h = t95(len(_pp) - 1) * st.stdev(_pp) / len(_pp) ** 0.5
    pair["pctCI95Process"] = [st.mean(_pp) - _h, st.mean(_pp) + _h]  # the relative overhead, process as the unit
    return pair


if PS:
    N["pair"] = pair_stats(PS)
# an earlier complete session of the same design, reported as a replication of the relative overhead
if SESS.get("pairReplication") and SESS["pairReplication"] != PS:
    _rs = SESS["pairReplication"]
    assert _rs not in INVALID, f"replication session {_rs} was declared invalid"
    _rp = [r for r in _pr if r["session"] == _rs]
    assert len(_procs(_rp)) >= 2 and len({len(v) for v in _procs(_rp).values()}) == 1 and len(_rp) >= 200, "incomplete replication"
    N["pairReplication"] = pair_stats(_rs)
    # power state of its paired steps, from its snapshots
    _ra = [r for r in jl("bench_env.jsonl") if r.get("session") == _rs and r["label"].startswith("after-pair")]
    N["pairReplication"]["pairStepsOnAC"] = sum(r.get("onAC") is True for r in _ra)
    N["pairReplication"]["pairSteps"] = len(_ra)
# warm-up pairs of the paired harnesses: their WARM default, since run_cpu_suite.sh does not set WARM
assert "WARM" not in (ROOT / "scripts" / "run_cpu_suite.sh").read_text(encoding="utf-8")
_warm = lambda f: int(re.search(r"WARM = Number\(process\.env\.WARM \|\| (\d+)\)", (ROOT / "scripts" / f).read_text(encoding="utf-8")).group(1))
N["bench.pairWarm"] = {"node": _warm("bench_pair.js"), "chrome": _warm("bench_browser.js")}
# Chrome, paired in pages (bench_browser.js)
_bp = jl("bench_browser_pair.jsonl")
BPS = pick(_bp, "browserPair", lambda rs: len(rs) >= 40)
if BPS:
    bp = [r for r in _bp if r["session"] == BPS]
    d = [r["vcrln_d20"] - r["rln2_d20"] for r in bp]
    pages = sorted({r.get("page", 0) for r in bp})
    if len(pages) > 1:  # the page is the unit, as the process is in Node
        per = [st.mean(r["vcrln_d20"] - r["rln2_d20"] for r in bp if r.get("page", 0) == pg) for pg in pages]
        half, unit = t95(len(per) - 1) * st.stdev(per) / len(per) ** 0.5, "pages"
    else:
        half, unit = 1.96 * st.stdev(d) / len(d) ** 0.5, "pairs within one page"
    b_ = st.mean(r["rln2_d20"] for r in bp)
    first = [r["vcrln_d20"] - r["rln2_d20"] for r in bp if r["first"] == "vcrln_d20"]
    second = [r["vcrln_d20"] - r["rln2_d20"] for r in bp if r["first"] == "rln2_d20"]
    N["browserPair"] = {"session": BPS, "pairs": len(d), "pages": len(pages), "pairsPerPage": len(d) // len(pages), "unit": unit,
                        "ours": st.mean(r["vcrln_d20"] for r in bp), "rln2": b_, "diff": st.mean(d), "pct": 100 * st.mean(d) / b_,
                        "ci95": [st.mean(d) - half, st.mean(d) + half], "ci95Pct": [100 * (st.mean(d) - half) / b_, 100 * (st.mean(d) + half) / b_],
                        # pairs per page may be odd, so the order is not balanced; the balanced estimate weights both orders equally
                        "orderEffect": {"oursFirst": st.mean(first), "oursSecond": st.mean(second), "nFirst": len(first), "nSecond": len(second)},
                        "balancedDiff": (st.mean(first) + st.mean(second)) / 2}
# machine conditions over every cited timing session. Snapshots labelled after-* close a timed step; before-suite
# snapshots are idle checks. Every step must have ended on mains power unless sessions.json gives a reason
# ("acceptBattery") to cite a battery session, which the paper then reports.
_BSESSION = pick([r for r in jl("bench_browser_runs.jsonl") if r.get("session")], "browser",
                 lambda rs: all(sum(1 for r in rs if r["name"] == n and r["pass"] == p and not r.get("cold")) >= 20
                                for n in ("vcrln_d20", "rln2_d20") for p in ("forward", "reverse")))
_cited = {SESSION, PS, CS, TS, _BSESSION, BPS} - {None}
_env = [r for r in jl("bench_env.jsonl") if r.get("session") in _cited]
if _env:
    steps = [r for r in _env if r["label"].startswith("after-")]
    on_ac = [r for r in steps if r.get("onAC") is True]
    first_batt = next((r["label"][len("after-"):] for r in steps if r.get("onAC") is not True), None)
    if len(on_ac) != len(steps):
        assert SESS.get("acceptBattery"), "a cited session ran on battery and sessions.json gives no acceptBattery reason"
    loads = [r["cpuLoadMean"] for r in _env if r.get("cpuLoadMean") is not None]
    N["bench.env"] = {"sessions": sorted({r["session"] for r in _env}), "loadMeanMin": min(loads), "loadMeanMax": max(loads),
                      "loadPeak": max(r.get("cpuLoadMax") or 0 for r in _env),
                      "powerPlans": sorted({r.get("powerPlan") for r in _env if r.get("powerPlan")}),
                      "steps": len(steps), "stepsOnAC": len(on_ac), "firstBatteryStep": first_batt,
                      "idleChecksOnAC": all(r.get("onAC") is True for r in _env if r["label"] == "before-suite"),
                      "acceptBattery": SESS.get("acceptBattery")}
    batt = [r["batteryPct"] for r in _env if r.get("batteryPct") is not None]
    N["bench.env"]["batteryPct"] = {"first": batt[0], "last": batt[-1]} if batt else None
    # processor performance ("% Processor Performance", _Total over all logical processors, relative to the base
    # frequency) from the suite's monitor (sessions before 27 Oct have none), only inside timed steps: a step runs from
    # the end of the snapshot before it to the start of its own after-* snapshot, so idle checks and snapshots are out
    _t = datetime.fromisoformat  # Python 3.11+: accepts "Z" and 7-digit fractions
    wins = []
    for sid in sorted(_cited):
        snaps = [r for r in _env if r["session"] == sid]
        for k, r in enumerate(snaps):
            if r["label"].startswith("after-") and k > 0:
                wins.append((sid, _t(snaps[k - 1]["ts"]), _t(r["ts"]) - timedelta(seconds=r.get("seconds") or 0)))
    perf = []
    for sid in sorted(_cited):
        m = ROOT / "data" / f"power_{sid.replace(':', '-')}.log"
        if not m.exists():
            continue
        for l in m.read_text(encoding="utf-8").splitlines():
            f = l.split(",")
            if len(f) == 3 and f[2] and any(w[0] == sid and w[1] <= _t(f[0]) <= w[2] for w in wins):
                perf.append(float(f[2]))
    if perf:
        N["bench.env"]["processorPerfPct"] = {"min": min(perf), "median": st.median(perf), "max": max(perf), "samples": len(perf),
                                              "scope": "inside timed steps"}

write_csv("table2_circuit.csv", ["config", "constraints", "zkey MB", "n", "prove mean ms", "sd", "p50", "p95", "witness ms", "verify ms"],
          [[r["name"], r["constraints"], f'{r["zkeyMB"]:.2f}', r.get("n", ""), *(f'{r[k]:.1f}' if k in r else "" for k in ("mean", "sd", "p50", "p95", "witness")),
            f'{r["verify"]:.2f}' if "verify" in r else ""] for r in rows])

# ---- functional tests ---------------------------------------------------------------------------------
t = json.loads((DATA / "tests_circuit.json").read_text(encoding="utf-8")) if (DATA / "tests_circuit.json").exists() else None
if t:
    N["tests.passed"], N["tests.total"] = t["passed"], t["total"]
    N["tests.groups"] = len({re.match(r"(T\d+)", r["name"]).group(1) for r in t["results"]})
rt = json.loads((DATA / "tests_registry.json").read_text(encoding="utf-8")) if (DATA / "tests_registry.json").exists() else None
if rt:
    N["testsRegistry.passed"], N["testsRegistry.total"] = rt["passed"], rt["total"]
    N["testsRegistry.groups"] = len({re.match(r"(R\d+)", r["name"]).group(1) for r in rt["results"]})

# ---- gas: local (current mainnet rules) and the three live networks --------------------------------
local = jl("gas_local.jsonl")
N["local.hardfork"] = local[0]["hardfork"] if local else None


def g(recs, op, n=None, phase=None):
    xs = [r["gasUsed"] for r in recs if r.get("op") == op and (n is None or r.get("n") == n) and (phase is None or r.get("phase") == phase)]
    return st.median(xs) if xs else None


tn = jl("testnet.jsonl")
complete = {}
seg = {}  # records written before run ids existed: a run starts at its ERC-1056 deployment
for r in tn:
    if r.get("op") == "deploy:EthereumDIDRegistry" or r["net"] not in seg:
        seg[r["net"]] = r.get("run") or r["txHash"]
    complete.setdefault(r["net"], {}).setdefault(r.get("run") or seg[r["net"]], []).append(r)
live = {}
for net, byrun in complete.items():
    ok = [recs for recs in byrun.values() if any(x["op"] == "PostBoard.post" for x in recs) and sum(x["op"] == "revokeLeaves" for x in recs) == 10]
    if ok:
        live[net] = ok[-1]
ops = [("first publication (1 leaf)", "addLeaves", 1, "first"), ("ring filling (1 leaf)", "addLeaves", 1, "fill"), ("publish 1 leaf", "addLeaves", 1, "steady"), ("publish 16 leaves", "addLeaves", 16, "steady"),
       ("publish 128 leaves", "addLeaves", 128, "steady"), ("revoke 1 leaf", "revokeLeaves", 1, None), ("per-root design: publish 1 leaf", "map.addLeaves", 1, "steady"),
       ("on-chain post (baseline)", "PostBoard.post", 1, None)]
nets = ["sepolia", "opSepolia", "arbSepolia"]
gas_rows = []
for label, op, n, ph in ops:
    lg = g(local, op, n, ph if op != "PostBoard.post" else None) if op != "revokeLeaves" else g(local, op, n)
    row = [label, lg] + [g(live[x], op, n, ph) if x in live else None for x in nets]
    gas_rows.append(row)
    N[f"gas.{op}.{n}.{ph}"] = dict(zip(["local", *nets], row[1:]))
write_csv("table3_gas.csv", ["operation", f"local ({N['local.hardfork']})", "Sepolia (Glamsterdam)", "OP Sepolia", "Arbitrum Sepolia"], gas_rows)
s128 = N.get("gas.addLeaves.128.steady", {})
if s128.get("local"):
    N["perMember.gas.local"] = s128["local"] / 128
    N["perMember.gas.arb"] = s128["arbSepolia"] / 128 if s128.get("arbSepolia") else None
    N["perMember.gas.sepolia"] = s128["sepolia"] / 128 if s128.get("sepolia") else None
    # marginal cost per leaf: execution-bound below the EIP-7623 floor (1 -> 16 leaves), and the floor's own slope
    # computed from the actual calldata (10 gas per token; a zero byte is 1 token, a non-zero byte 4)
    N["marginal.gasPerLeaf.1to16.local"] = (N["gas.addLeaves.16.steady"]["local"] - N["gas.addLeaves.1.steady"]["local"]) / 15
    _txin = {(x["op"], x["n"]): x for x in json.loads((DATA / "tx_inputs.json").read_text(encoding="utf-8"))} if (DATA / "tx_inputs.json").exists() else {}

    def floor_gas(data_hex):
        b = bytes.fromhex(data_hex[2:])
        return 21000 + 10 * sum(1 if x == 0 else 4 for x in b)
    if ("addLeaves", 1) in _txin and ("addLeaves", 128) in _txin:
        f1, f128 = floor_gas(_txin[("addLeaves", 1)]["data"]), floor_gas(_txin[("addLeaves", 128)]["data"])
        slope_exec, slope_floor = N["marginal.gasPerLeaf.1to16.local"], (f128 - f1) / 127
        N["floor"] = {"leaf1": f1, "leaf128": f128, "gasPerLeaf": slope_floor, "batch128EqualsFloor": f128 == _txin[("addLeaves", 128)]["gasUsedOp"],  # same transaction
                      "crossoverLeaves": 1 + (N["gas.addLeaves.1.steady"]["local"] - f1) / (slope_floor - slope_exec)}

# ring registry: fill-phase cost and the publication count after which the ring is cheaper in total than one
# storage slot per root (per-root design: first publication, then steady)
for where in ("local", "sepolia"):
    src = local if where == "local" else live.get("sepolia", [])
    first, fill, steady = g(src, "addLeaves", 1, "first"), g(src, "addLeaves", 1, "fill"), g(src, "addLeaves", 1, "steady")
    mfirst, msteady = g(src, "map.addLeaves", 1, "first"), g(src, "map.addLeaves", 1, "steady")
    if None in (first, fill, steady, mfirst, msteady):
        continue
    ring = lambda k: first + fill * min(k - 1, 15) + steady * max(k - 16, 0)
    perroot = lambda k: mfirst + msteady * (k - 1)
    N[f"ring.{where}"] = {"first": first, "fill": fill, "steady": steady, "perRootFirst": mfirst, "perRootSteady": msteady,
                          "fillVsPerRootPct": 100 * (fill / msteady - 1), "steadySavingPct": 100 * (1 - steady / msteady),
                          "breakEvenPublications": next(k for k in range(1, 10_000) if ring(k) <= perroot(k))}

# Glamsterdam (Sepolia) against current rules (local), every row of Table III
inc = {}
for label, op, n, ph in ops:
    d = N[f"gas.{op}.{n}.{ph}"]
    if d.get("local") and d.get("sepolia"):
        inc[label] = 100 * (d["sepolia"] / d["local"] - 1)
N["glamsterdam.increasePct"] = inc

# ---- revocation lag (spread-out rerun: random 120-240 s gaps, reader on a different RPC provider) ----------
lag = {}
rl = jl("revocation_lag.jsonl")
for net in nets:
    recs = [r for r in rl if r["net"] == net]
    if not recs:
        continue
    run = recs[-1]["run"]
    rv = [r for r in recs if r["run"] == run]
    inc_ = [r["inclusionMs"] for r in rv]
    vis = [r["visibleMs"] for r in rv if r.get("visibleMs") is not None]
    from datetime import datetime
    tss = [datetime.fromisoformat(r["ts"].replace("Z", "+00:00")) for r in rv]
    gaps = [(b - a).total_seconds() for a, b in zip(tss, tss[1:])]
    lag[net] = {"n": len(rv), "timeouts": len(rv) - len(vis), "reader": rv[0]["reader"], "pollMs": rv[0]["pollMs"],
                "send_median_s": st.median(r["sendMs"] for r in rv) / 1000, "send_max_s": max(r["sendMs"] for r in rv) / 1000,
                "gap_min_s": min(gaps), "gap_max_s": max(gaps),
                "inclusion_median_s": st.median(inc_) / 1000, "inclusion_max_s": max(inc_) / 1000,
                "visible_median_s": st.median(vis) / 1000 if vis else None, "visible_p90_s": q(vis, .9) / 1000 if vis else None,
                "visible_min_s": min(vis) / 1000 if vis else None, "visible_max_s": max(vis) / 1000 if vis else None,
                "max_is_first": bool(vis) and vis.index(max(vis)) == 0, "from": rv[0]["ts"], "to": rv[-1]["ts"]}
N["revocationLag"] = lag

# ---- mainnet fees (median and interquartile range over the frozen sample window) -------------------------
import fees as feemod
# Arbitrum receipt gas can include an L1-data component. The cited testnet runs
# have zero data gas; fail closed on a future run until that component is removed
# before adding the independently estimated mainnet data fee.
assert all(r.get("gasUsedForL1") is not None and int(r["gasUsedForL1"]) == 0 for r in live.get("arbSepolia", [])), \
    "Arbitrum extrapolation needs execution-only gas when saved L1 data gas is nonzero"
mf = feemod.samples()
N["mainnet.sampling"] = feemod.window(mf)
txin = json.loads((DATA / "tx_inputs.json").read_text(encoding="utf-8")) if (DATA / "tx_inputs.json").exists() else []
gas_main = {(x["op"], x["n"]): x for x in txin}
# L2 gas from the complete runs used in Table III (tx_inputs.json took it from the first matching record)
for (op, n), x in gas_main.items():
    ph = "steady" if op == "addLeaves" else None
    if "opSepolia" in live:
        x["gasUsedOp"] = g(live["opSepolia"], op, n, ph)
    if "arbSepolia" in live:
        x["gasUsedArb"] = g(live["arbSepolia"], op, n, ph)
fees = defaultdict(lambda: defaultdict(list))
for r in mf:
    ob, ot = int(r["op"]["baseFeeWei"]), int(r["op"]["tipWei"])
    ab, eb, et = int(r["arb"]["baseFeeWei"]), int(r["eth"]["baseFeeWei"]), int(r["eth"]["tipWei"])
    for x in r["op"]["tx"]:
        k = (x["op"], x["n"])
        ge = gas_main[k]["gasUsedOp"]
        l1 = int(x["l1FeeWei"]) + int(x["operatorFeeWei"] or 0)
        fees[k]["op_base"].append(ge * ob + l1)
        fees[k]["op_tip"].append(ge * (ob + ot) + l1)
        fees[k]["op_l1share_base"].append(l1 / (ge * ob + l1))
    for x in r["arb"]["tx"]:
        k = (x["op"], x["n"])
        ga = gas_main[k]["gasUsedArb"] or gas_main[k]["gasUsedOp"]
        fees[k]["arb"].append((ga + int(x["gasEstimateForL1"])) * ab)
    for k, x in gas_main.items():
        gl = g(local, k[0], k[1], "steady" if k[0] == "addLeaves" else None)
        fees[k]["eth_base"].append(gl * eb)
        fees[k]["eth_tip"].append(gl * (eb + et))
N["mainnet.samples"] = len(mf)
N["mainnet.window"] = [mf[0]["ts"], mf[-1]["ts"]] if mf else None
N["mainnet.ethBaseFeeWei"] = {"median": st.median(int(r["eth"]["baseFeeWei"]) for r in mf),
                              "min": min(int(r["eth"]["baseFeeWei"]) for r in mf), "max": max(int(r["eth"]["baseFeeWei"]) for r in mf)}
fee_rows = []
for k in sorted(fees, key=lambda k: (k[0], k[1])):
    d = {}
    for col, xs in fees[k].items():
        d[col] = {"median": st.median(xs), "q1": q(xs, .25), "q3": q(xs, .75)}
    N[f"mainnetFee.{k[0]}.{k[1]}"] = d
    fee_rows.append([f"{k[0]}({k[1]})"] + [f'{d[c]["median"] / 1e9:.4g}' if c in d else "" for c in ("eth_base", "eth_tip", "op_base", "op_tip", "arb")])
write_csv("table3b_mainnet_fees_gwei_units.csv", ["operation (fee in 1e-9 ETH, median)", "Ethereum base", "Ethereum +tip", "OP base", "OP +tip", "Arbitrum"], fee_rows)
for col in ("eth_base", "eth_tip", "op_base", "op_tip", "arb"):
    k = ("addLeaves", 128)
    if k in fees and col in fees[k]:
        N[f"perMember.fee.{col}.ETH"] = st.median(fees[k][col]) / 128 / 1e18

# ---- end-to-end DID + VC + ZKP run ----------------------------------------------------------------------
vc = DATA / "vc_demo.json"
if vc.exists():
    N["vcDemo"] = json.loads(vc.read_text(encoding="utf-8"))["steps"]

# ---- browser proving (headless Chrome, same laptop) ----------------------------------------------------
_bb = [r for r in jl("bench_browser_runs.jsonl") if r.get("session")]
BSESSION = pick(_bb, "browser", lambda rs: all(sum(1 for r in rs if r["name"] == n and r["pass"] == p and not r.get("cold")) >= 20
                                               for n in ("vcrln_d20", "rln2_d20") for p in ("forward", "reverse")))
N["browser.session"] = BSESSION
br, bcold = defaultdict(list), defaultdict(list)
for r in _bb:
    if r["session"] == BSESSION:
        (bcold if r.get("cold") else br)[r["name"]].append(r["totalMs"])
for name, xs in br.items():
    N[f"browser.{name}"] = {"n": len(xs), "mean": st.mean(xs), "sd": st.stdev(xs), "p50": q(xs, .5), "p95": q(xs, .95),
                            "coldMean": st.mean(bcold[name]) if bcold[name] else None}
bs = [r for r in jl("bench_browser.jsonl") if r.get("session") == BSESSION]
if bs:
    N["browser.version"], N["browser.threads"] = bs[0]["browser"], bs[0]["threads"]
if "vcrln_d20" in br and "rln2_d20" in br:
    a, b = st.mean(br["vcrln_d20"]), st.mean(br["rln2_d20"])
    N["browser.overheadMs"], N["browser.overheadPct"] = a - b, 100 * (a - b) / b

# ---- constraint breakdown and policy agility ------------------------------------------------------------
for name in ("constraint_breakdown", "agility"):
    p = DATA / f"{name}.json"
    if p.exists():
        N[name] = json.loads(p.read_text(encoding="utf-8"))
N["gas.revokeLeaves.128.local"] = g(local, "revokeLeaves", 128)
N["gas.revokeLeaves.16.local"] = g(local, "revokeLeaves", 16)
# values the method text states, read from the records instead of typed in
N["testnet.txPerNetwork"] = {net: len(recs) for net, recs in live.items()}
_w = re.search(r"WINDOW = (\d+)", (ROOT / "scripts" / "testnet.js").read_text(encoding="utf-8"))
N["testnet.windowS"] = int(_w.group(1)) if _w else None
if "agility" in N:
    assert N["agility"]["measured"]["feeSamples"] == len(mf), "agility.json was computed from another fee sample set: rerun agility.py"

out = json.dumps(N, indent=1, default=float)
(DATA / "paper_numbers.json").write_text(out, encoding="utf-8", newline="\n")
print(out)
