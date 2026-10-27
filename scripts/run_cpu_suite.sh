#!/usr/bin/env bash
# Every CPU-timed measurement of the paper in one session, on an idle laptop on mains power:
#   1 Node sweep over tree depths (bench.sh), 2 paired depth-20 benchmark in PAIR_PROCS processes, 3 cold first proofs
#   in fresh processes (COLD_ROUNDS per circuit, alternating), 4 tree cost at the modeled size, 5 Chrome sweep and
#   paired run in several fresh pages. Before starting it waits until two consecutive 20-s load readings on mains
#   power are at most MAX_LOAD percent. A monitor logs power source and processor performance about every 2 s
#   (data/power_<session>.log); a step during which power left mains ends the session (exit 3) and the session is
#   recorded as invalid in data/invalid_sessions.txt. A snapshot (load, peak, busiest processes, power) follows every
#   step and goes to data/bench_env.jsonl. No transaction is sent.
#   bash scripts/run_cpu_suite.sh
set -euo pipefail
cd "$(dirname "$0")/.."
MAX_LOAD="${MAX_LOAD:-15}" PAIR_PROCS="${PAIR_PROCS:-4}" PAIRS="${PAIRS:-100}" COLD_ROUNDS="${COLD_ROUNDS:-10}" TREE_M="${TREE_M:-100000}"
export SESSION="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
PUPPETEER_CORE="${PUPPETEER_CORE:-puppeteer-core}"  # the devDependency unless set
export PUPPETEER_CORE
MON="data/power_${SESSION//:/-}.log" STOP="data/.monitor_stop_${SESSION//:/-}"
snap() { powershell -NoProfile -ExecutionPolicy Bypass -File scripts/env_snapshot.ps1 -Session "$SESSION" -Label "$1" -Seconds "${2:-20}" | tee -a data/bench_env.jsonl; }
load_of() { node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const j=JSON.parse(s);console.log(j.onAC&&j.cpuLoadMean!=null?j.cpuLoadMean:999)})'; }
log() { echo "== $(date -u +%H:%M:%S) $*" | tee -a data/cpu_suite.log; }
invalid() { log "$1: session $SESSION is invalid"; echo "$SESSION $1" >> data/invalid_sessions.txt; touch "$STOP"; exit 3; }
mark=0
step_begin() { mark=$(wc -l < "$MON" 2>/dev/null || echo 0); }
# a step counts only if every monitor line written during it shows mains power, and its closing snapshot does too
checked() {
  if tail -n +"$((mark + 1))" "$MON" | grep -v ',Online,' | grep -q .; then invalid "power left mains during '$1'"; fi
  local s; s="$(snap "$1")"; echo "$s" | grep -q '"onAC":true' || invalid "battery at the end of '$1'"
}
trap 'touch "$STOP"' EXIT

powershell -NoProfile -ExecutionPolicy Bypass -File scripts/env_monitor.ps1 -Out "$MON" -Stop "$STOP" &
log "session $SESSION: waiting for an idle machine on mains power (two readings <= $MAX_LOAD%)"
sleep "${SETTLE_S:-60}"
ok=0
for try in $(seq 1 "${TRIES:-20}"); do
  l="$(snap "before-suite" | load_of)"
  log "check $try: load $l%"
  if [ "$(node -e "console.log($l <= $MAX_LOAD ? 1 : 0)")" = 1 ]; then ok=$((ok + 1)); else ok=0; fi
  [ "$ok" -ge 2 ] && break
  [ "$try" = "${TRIES:-20}" ] && { log "load stayed above $MAX_LOAD% or power was not mains: not running"; exit 2; }
done

log "1 Node sweep"; step_begin; bash scripts/bench.sh >> data/bench.log 2>&1; checked "after-sweep" > /dev/null
log "2 paired benchmark"
for p in $(seq 1 "$PAIR_PROCS"); do step_begin; PROC="p$p" node scripts/bench_pair.js "$PAIRS" >> data/bench_pair.log 2>&1; checked "after-pair-p$p" > /dev/null; done
log "3 cold first proofs"; step_begin
for r in $(seq 1 "$COLD_ROUNDS"); do
  if [ $((r % 2)) = 1 ]; then order="vcrln_d20 rln2_d20"; else order="rln2_d20 vcrln_d20"; fi
  for c in $order; do node scripts/bench_cold.js "$c" >> data/bench_cold.log 2>&1; done
done
checked "after-cold" > /dev/null
log "4 tree cost"; step_begin; node scripts/bench_tree.js "$TREE_M" >> data/bench_tree.log 2>&1; checked "after-tree" > /dev/null
log "5 Chrome"; step_begin; node scripts/bench_browser.js >> data/bench_browser.log 2>&1; checked "after-browser" > /dev/null
log "done $SESSION"
