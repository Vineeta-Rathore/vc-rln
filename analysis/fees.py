"""Mainnet fee samples used by the paper: one fixed window, the same filter everywhere.
The sampler (scripts/mainnet_fee_sampler.js) appends to data/mainnet_fees.jsonl; samples outside the window, or with
a read error on any of the three chains, are left out, and so is the second of two samples taken within the same
5 minutes (the sampler was started twice at 22:10Z). Re-running the analysis later gives the same numbers.
"""
import json
from datetime import datetime
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"
# Include all completed collections, including the resumed third run. Historical failed
# readings remain in the raw file; run-3 provenance records its interruptions and completion.
# The fixed cutoff includes the last reading at 29 Oct 03:34Z without selecting by price.
FEE_FROM, FEE_TO = "2026-10-25T22:00:00Z", "2026-10-29T04:00:00Z"


def _t(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def samples():
    rows = [json.loads(l) for l in (DATA / "mainnet_fees.jsonl").read_text(encoding="utf-8").splitlines() if l.strip()]
    lo, hi = _t(FEE_FROM), _t(FEE_TO)
    rows = sorted((r for r in rows if lo <= _t(r["ts"]) <= hi), key=lambda r: r["ts"])
    out, last = [], None
    for r in rows:
        if last is not None and (_t(r["ts"]) - last).total_seconds() < 300:
            continue
        last = _t(r["ts"])
        if not (r["op"].get("error") or r["arb"].get("error") or r["eth"].get("error")):
            out.append(r)
    return out


def window(rows):
    """First and last sample time and the longest gap between samples, in minutes."""
    ts = sorted(_t(r["ts"]) for r in rows)
    gaps = [(b - a).total_seconds() / 60 for a, b in zip(ts, ts[1:])]
    return {"from": rows and min(r["ts"] for r in rows), "to": rows and max(r["ts"] for r in rows), "n": len(rows),
            "maxGapMin": max(gaps) if gaps else None, "medianGapMin": sorted(gaps)[len(gaps) // 2] if gaps else None,
            "hoursOfDayCovered": len({t.hour for t in ts}), "spanHours": (ts[-1] - ts[0]).total_seconds() / 3600 if ts else 0}
