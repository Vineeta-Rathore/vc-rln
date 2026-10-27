"""The on-chain trail the paper cites, for the checking tools: data/transactions.csv (every cited transaction with its
network, operation and gas) and data/registries.json (the registry and issuer of each gas run, for replaying its event
log); and the end-to-end credential in vc_check/credential.json, which vc_check/independent_vc_check.mjs checks.
   python analysis/export_transactions.py        (run after the testnet runs and vc_demo.js; see analysis/run_all.sh)
"""
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"


def jl(name):
    p = DATA / name
    return [json.loads(l) for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []


# the runs Table III uses (same selection as paper_numbers.py)
tn = jl("testnet.jsonl")
complete, seg = {}, {}
for r in tn:
    if r.get("op") == "deploy:EthereumDIDRegistry" or r["net"] not in seg:
        seg[r["net"]] = r.get("run") or r["txHash"]
    complete.setdefault(r["net"], {}).setdefault(r.get("run") or seg[r["net"]], []).append(r)
live = {}
for net, byrun in complete.items():
    ok = [recs for recs in byrun.values() if any(x["op"] == "PostBoard.post" for x in recs) and sum(x["op"] == "revokeLeaves" for x in recs) == 10]
    if ok:
        live[net] = ok[-1]

rows = []
for net, recs in live.items():
    for r in recs:
        rows.append({"source": "gas run (Table III)", "network": net, "operation": r["op"], "leaves": r.get("n"), "phase": r.get("phase") or "",
                     "txHash": r["txHash"], "block": r["block"], "contract": r.get("contract") or "", "gasUsed": r["gasUsed"]})
rl = jl("revocation_lag.jsonl")
for net in ("sepolia", "opSepolia", "arbSepolia"):
    recs = [r for r in rl if r["net"] == net]
    if recs:
        run = recs[-1]["run"]
        for r in recs:
            if r["run"] == run:
                rows.append({"source": "revocation lag", "network": net, "operation": "revokeLeaves", "leaves": 1, "phase": "",
                             "txHash": r["txHash"], "block": r["block"], "contract": "", "gasUsed": r["gasUsed"]})
vc = json.loads((DATA / "vc_demo.json").read_text(encoding="utf-8"))
for step, op in (("setKey", "ERC1056.setAttribute (issuer key)"), ("enrol", "addLeaves"), ("anchorPolicy", "ERC1056.setAttribute (policy form)")):
    st_ = vc["steps"][step]
    rows.append({"source": "end-to-end run", "network": "opSepolia", "operation": op, "leaves": 1 if step == "enrol" else "",
                 "phase": "", "txHash": st_["txHash"], "block": "", "contract": "", "gasUsed": st_["gasUsed"]})
# the transaction whose calldata the EIP-7623 floor check and the mainnet fee estimates used (an earlier OP Sepolia run)
for x in json.loads((DATA / "tx_inputs.json").read_text(encoding="utf-8")):
    if x["op"] == "addLeaves" and x["n"] == 128:
        rows.append({"source": "fee and floor calldata", "network": "opSepolia", "operation": "addLeaves", "leaves": 128, "phase": "steady",
                     "txHash": x["txHash"], "block": "", "contract": x["to"], "gasUsed": x["gasUsedOp"]})

with open(DATA / "transactions.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
    w.writeheader()
    w.writerows(rows)
# registries whose event log can be replayed: the gas runs and the end-to-end run
regs = []
for net, recs in live.items():
    reg = next(r for r in recs if r["op"] == "deploy:IssuerRootRegistry")
    regs.append({"network": net, "registry": reg["contract"], "deployBlock": reg["block"], "issuer": vc["vc"]["issuer"].split(":")[-1],
                 "erc1056": next(r for r in recs if r["op"] == "deploy:EthereumDIDRegistry")["contract"]})
(DATA / "registries.json").write_text(json.dumps(regs, indent=1), encoding="utf-8", newline="\n")

(ROOT / "vc_check" / "credential.json").write_text(json.dumps(vc["vc"], indent=1) + "\n", encoding="utf-8", newline="\n")
print(f"{len(rows)} transactions, {len(regs)} registries")
