"""Policy agility: leaf operations (one added or revoked leaf = one operation) a platform publishes per month when
limits depend on attributes that change, for two RLN v2 deployments and our design. A model built on measured gas
(data/gas_local.jsonl, current mainnet rules); the platform figures are assumptions, stated below and in the paper.

  RLN v2, one tree per community: the limit is fixed in the leaf (rateCommitment = H(H(s), limit)), so each
    community with its own limits has its own tree. A new member is C additions; a member whose limit changes in a
    community is a replacement (revoke + add) in that community's tree; a policy change replaces the leaves of the
    affected share alpha of the members in that community.
  hidden-tier variant (RLN v2 with a tier): one tree; the leaf commits a tier and each community publishes a tier -> limit table. Policy
    changes need no leaf operation, but every change of tier is one replacement.
  Ours: one tree; the limit is computed in the proof from attributes and the community policy. Only an attribute
    change (becoming verified) is a replacement; seniority is a date compared in the proof.

Per month, with M members, C communities, n new members, V members becoming verified, K policy changes and X
seniority crossings (X = 0 without seniority cutoffs; X = n with one cutoff shared by all communities, since in
steady state every new member crosses it once; X = C*n with a separate cutoff per community):
  RLN v2 per community: C*n + 2*C*(n_s + V) + 2*K*alpha*M   with n_s = n if there is any seniority cutoff, else 0
                        (a shared crossing changes the limit in all C trees; C separate crossings change one each)
  hidden-tier variant:  n + 2*(X + V)
  ours:                 n + 2*V
so the ratio of the tier design to ours is 1 + 2X/(n + 2V).
   python analysis/agility.py     (writes data/agility.json)
"""
import json
import statistics as st
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", newline="\n")  # LF on every platform (data/SHA256SUMS)
sys.path.insert(0, str(Path(__file__).resolve().parent))
import fees as feemod  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data"

# assumptions (illustrative platform, per month)
A = {
    "members": 100_000,
    "communities": 4,            # communities whose limits differ; every member is in all of them (upper bound)
    "newMembers": 5_000,         # 5% monthly growth
    "cutoffs": "shared",         # seniority cutoffs: none | shared | per-community
    "verifications": 2_000,      # members whose verified-human attribute changes
    "policyChanges": 1,          # communities that change their limits in the month
    "affectedShare": 1.0,        # share of members whose limit changes when a community changes policy (upper bound)
    "batch": 128,
}

gas = [json.loads(l) for l in (DATA / "gas_local.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
add128 = st.median(r["gasUsed"] for r in gas if r.get("op") == "addLeaves" and r.get("n") == 128 and r.get("phase") == "steady")
rev128 = st.median(r["gasUsed"] for r in gas if r.get("op") == "revokeLeaves" and r.get("n") == 128)
add_leaf, rev_leaf = add128 / A["batch"], rev128 / A["batch"]

fee_rows = feemod.samples()
eth_base = st.median(int(r["eth"]["baseFeeWei"]) for r in fee_rows)


def crossings(a):
    return {"none": 0, "shared": a["newMembers"], "per-community": a["communities"] * a["newMembers"]}[a["cutoffs"]]


def monthly(a):
    """(additions, revocations) per month for each design."""
    M, C, n, V = a["members"], a["communities"], a["newMembers"], a["verifications"]
    X = crossings(a)
    ns = n if a["cutoffs"] != "none" else 0
    pol = a["policyChanges"] * a["affectedShare"] * M
    return {"rlnV2PerCommunity": (C * n + C * (ns + V) + pol, C * (ns + V) + pol),
            "rlnV2Tier": (n + X + V, X + V),
            "ours": (n + V, V)}


def cost(adds, revs):
    g = adds * add_leaf + revs * rev_leaf
    return {"additions": adds, "revocations": revs, "leafOps": adds + revs, "gas": round(g),
            "ETH_at_sampled_base_fee": g * eth_base / 1e18, "ETH_at_10_gwei": g * 10e9 / 1e18}


m = monthly(A)
out = {
    "assumptions": A,
    "formula": {"rlnV2PerCommunity": "C*n + 2*C*(n_s+V) + 2*K*alpha*M", "rlnV2Tier": "n + 2*(X+V)", "ours": "n + 2*V",
                "ratioTier": "1 + 2X/(n+2V)", "X": "0 (no cutoff), n (shared), C*n (per community)"},
    "gasRules": "current mainnet rules (Hardhat, Osaka)",
    "measured": {"addLeaves128": add128, "revokeLeaves128": rev128, "gasPerAddedLeaf": add_leaf, "gasPerRevokedLeaf": rev_leaf,
                 "gasPerReplacement": add_leaf + rev_leaf, "ethBaseFeeMedianWei": eth_base, "feeSamples": len(fee_rows)},
    "enrolment": {"rlnV2PerCommunity": cost(A["members"] * A["communities"], 0), "rlnV2Tier": cost(A["members"], 0), "ours": cost(A["members"], 0)},
    "monthly": {k: cost(*v) for k, v in m.items()},
}
ours_ops = out["monthly"]["ours"]["leafOps"]
out["monthly"]["ratio"] = {k: out["monthly"][k]["leafOps"] / ours_ops for k in ("rlnV2PerCommunity", "rlnV2Tier")}
# sensitivity of the ratios (baseline / ours) to the seniority cutoffs, C, K, alpha and V
out["sensitivity"] = []
for cut in ("none", "shared", "per-community"):
    for c in (1, 2, 4):
        for k in (0, 1):
            for alpha in ((0.25, 1.0) if k else (1.0,)):
                for v in (2_000, 5_000):
                    a = {**A, "cutoffs": cut, "communities": c, "policyChanges": k, "affectedShare": alpha, "verifications": v}
                    mm = monthly(a)
                    o = sum(mm["ours"])
                    out["sensitivity"].append({"cutoffs": cut, "communities": c, "policyChanges": k, "affectedShare": alpha, "verifications": v,
                                               "vsPerCommunity": sum(mm["rlnV2PerCommunity"]) / o, "vsTier": sum(mm["rlnV2Tier"]) / o})
rng = lambda key, cut=None: [f(s[key] for s in out["sensitivity"] if cut is None or s["cutoffs"] == cut) for f in (min, max)]
out["sensitivityRange"] = {"vsPerCommunity": rng("vsPerCommunity"), "vsTier": rng("vsTier"),
                           "vsTierByCutoffs": {cut: rng("vsTier", cut) for cut in ("none", "shared", "per-community")},
                           "vsPerCommunityByCutoffs": {cut: rng("vsPerCommunity", cut) for cut in ("none", "shared", "per-community")}}
(DATA / "agility.json").write_text(json.dumps(out, indent=1), encoding="utf-8", newline="\n")
print(json.dumps({k: out[k] for k in ("monthly", "sensitivityRange")}, indent=1))
