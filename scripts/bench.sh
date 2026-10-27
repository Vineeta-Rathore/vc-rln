#!/usr/bin/env bash
# Two passes over all configurations, the second in reverse order, one fresh Node process per
# configuration, so drift over the session does not line up with tree depth.
set -euo pipefail
cd "$(dirname "$0")/.."
RUNS="${RUNS:-30}"
export SESSION="${SESSION:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"  # one id for every record of this sweep
CONFIGS="vcrln_d10 vcrln_d16 vcrln_d20 vcrln_d24 vcrln_d32 rln2_d20"
REVERSED="$(echo $CONFIGS | awk '{for (i = NF; i > 0; i--) printf "%s ", $i}')"  # no tac on macOS
for c in $CONFIGS;  do node scripts/bench_one.js "$c" "$RUNS" forward; done
for c in $REVERSED; do node scripts/bench_one.js "$c" "$RUNS" reverse; done
