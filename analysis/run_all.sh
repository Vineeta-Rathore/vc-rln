#!/usr/bin/env bash
# The analysis in the order its outputs depend on each other: optionally the tests (RUN_TESTS=1), the policy model
# (reads the frozen fee window), experimental results and model calculations (embeds agility.json and checks the fee
# samples), the on-chain trail for the checking tools, and the figures (read the cited benchmark session from
# paper_numbers.json). EXPORT_PROOFS=1 also writes new sample proofs (fresh randomness, so new files).
#   bash analysis/run_all.sh
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PY:-python3}"
if [ "${RUN_TESTS:-0}" = 1 ]; then
  node scripts/test_circuit.js > data/tests_circuit.log 2>&1
  npx hardhat run scripts/registry_test.js > data/tests_registry.log 2>&1
fi
"$PY" analysis/agility.py > data/agility.log
"$PY" analysis/paper_numbers.py > data/paper_numbers.log
"$PY" analysis/export_transactions.py
if [ "${EXPORT_PROOFS:-0}" = 1 ]; then node scripts/export_proofs.js; fi
"$PY" analysis/make_figures.py
echo "analysis done"
