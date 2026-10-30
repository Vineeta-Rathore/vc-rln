# Data

Raw measurements and derived files behind every table, figure and number of the paper. JSONL files hold one JSON
object per line; each line carries its session, run or timestamp, except the Hardhat gas files (`gas_local.jsonl`,
`superseded/gas_local_v1_maproot.jsonl`). `SHA256SUMS` lists the checksum of every data file.
Sessions that the paper does not cite stay in the files; `analysis/sessions.json` selects the cited ones and gives
the reason for each exclusion.

## Proving time and client cost (Section IV, Table II, Fig. 2, Sections V-A and V-D)

| File | Written by | Content |
|---|---|---|
| `bench_runs.jsonl` | `scripts/bench_one.js` | every timed Node.js proof: configuration, pass, run, witness, proving and total ms |
| `bench.jsonl` | `scripts/bench_one.js` | one summary per configuration and pass: constraints, key sizes, means, SDs, cold proof, verification |
| `bench_pair.jsonl` | `scripts/bench_pair.js` | paired depth-20 proofs of our circuit and RLN v2, alternating in one process |
| `bench_cold.jsonl` | `scripts/bench_cold.js` | first proofs in fresh processes |
| `bench_browser_runs.jsonl`, `bench_browser.jsonl` | `scripts/bench_browser.js` | Chrome proofs in separate pages, per run and per configuration |
| `bench_browser_pair.jsonl` | `scripts/bench_browser.js` | Chrome proofs alternating in fresh pages |
| `bench_tree.jsonl` | `scripts/bench_tree.js` | building a tree of 100,000 leaves, inserting a leaf, checking a path |
| `bench_env.jsonl` | `scripts/env_snapshot.ps1` | machine state before the suite and after each step: load, top processes, power, battery |
| `power_2026-10-27T03-06-54Z.log` | `scripts/env_monitor.ps1` | power source and processor performance every 2 s during the cited session |
| `constraint_breakdown.json` | `scripts/constraint_breakdown.js` | constraints of the pseudonym, the in-circuit external nullifier, the policy and a platform-wide cap |
| `cpu_suite.log`, `bench.log`, `bench_pair.log`, `bench_cold.log`, `bench_tree.log`, `bench_browser.log` | `scripts/run_cpu_suite.sh` | progress logs of the CPU sessions |
| other `*.log` files | the script named in the file name, output redirected by hand | progress and errors; `wait_ac.log` and `cpu_suite_run*.log` log the wait for mains power and the suite run |

## Gas, fees and revocation (Table III, Section V-B)

| File | Written by | Content |
|---|---|---|
| `gas_local.jsonl` | `scripts/gas_local.js` | gas on the Hardhat EVM (Osaka hardfork, the current mainnet rules) |
| `testnet.jsonl` | `scripts/testnet.js` | every transaction of the testnet runs: network, operation, hash, block, gas, timing |
| `revocation_lag.jsonl` | `scripts/revoke_lag.js` | 20 timed revocations per network: send, receipt and visibility to a second provider |
| `mainnet_fees.jsonl` | `scripts/mainnet_fee_sampler.js` | read-only OP Mainnet, Arbitrum One and Ethereum fee readings; `analysis/fees.py` fixes the window used |
| `mainnet_fees_run3_manifest.json` | integration of the completed third collection | segment labels, counts, timestamps and hashes; instructions to reconstruct each original segment from the unchanged raw lines |
| `tx_inputs.json` | `scripts/mainnet_fee_sampler.js` | calldata of one OP Sepolia transaction per operation, fetched once from the chain; the sampler prices it and the EIP-7623 floor check reads it. The three `addLeaves` entries come from an earlier OP Sepolia run of `testnet.js` (25 October 21:55 UTC); calldata size depends only on the leaf count |
| `transactions.csv`, `registries.json` | `analysis/export_transactions.py` | every cited transaction and the registries whose event logs `tools/` replays |

The completed fee snapshot has 348 raw rows. The fixed window from 25 October 22:00 UTC to 29 October 04:00 UTC
selects 337 successful matched readings after excluding ten rows with chain-read errors and one near-duplicate.
Successful readings span 77.4 hours and represent all 24 UTC hours of the day, with a 10.3-hour maximum gap.
The new third collection contains 145 complete readings; its interruption gaps remain visible in the timestamps.
The manifest's original segment files are reconstructible by filtering the raw JSONL lines by run label, preserving
their order and newline bytes. They are not separately required downloads.

## Design checks and the end-to-end run (Sections IV, V-D, VI)

| File | Written by | Content |
|---|---|---|
| `tests_circuit.json` | `scripts/test_circuit.js` | 49 circuit and client checks: name, expected and observed result |
| `tests_registry.json` | `scripts/registry_test.js` | 11 registry checks on the local EVM |
| `vc_demo.json` | `scripts/vc_demo.js` | the end-to-end run on OP Sepolia: transactions, timings, credential and every check |
| `vc_check.json` | `vc_check/independent_vc_check.mjs` | the independent credential check (Digital Bazaar and jsonld), copied from `vc_check/result.json` |
| `ptau_verify.log`, `build.log` | `snarkjs`, `scripts/build.sh` | verification of the phase-1 transcript and the circuit build |

## Derived files

`paper_numbers.json` and `.log` (every number the paper cites), `agility.json` and `.log` (Section V-C) and
`tables/` are written by `analysis/run_all.sh`. `superseded/` keeps the runs of an earlier registry version that
the paper does not use.

## License

CC BY 4.0 (see `LICENSE`).
