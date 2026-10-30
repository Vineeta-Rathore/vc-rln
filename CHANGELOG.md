# Changelog

## Unreleased (2026-10-30): final research review

- Reject a selected fee observation with an unavailable OP operator-fee component instead of counting it as zero.
  The 337 cited observations contain explicit components, so their selection and numerical results are unchanged.
- Reject empty network selections and invalid log steps before initializing the tree-checking tool. Add offline
  regressions for these inputs and for missing/null operator-fee components.
- Qualify data-availability claims, document the verification/tree summary exceptions and platform-dependent
  rendering, and correct the policy-cutoff comment. Record the author-approved paper acknowledgment and artifact
  AI assistance.
- The accompanying paper clarifies update ratios, model boundaries, boxplot encoding and observational privacy
  conditions; it removes an unsupported static-analysis assurance. No measurements or reference entries change.

## Unreleased (2026-10-30): completed fee collection

- Include all 145 readings from the completed third collection, preserving its two interrupted segments and
  manual continuation. Keep the previous 203 raw rows unchanged.
- Extend the fixed analysis cutoff to 29 October 04:00 UTC. The unchanged filter selects 337 successful matched
  readings over 77.4 hours and represents all 24 UTC hours of the day, with a 10.3-hour maximum gap.
- Record source-segment hashes and reconstruction instructions in `data/mainnet_fees_run3_manifest.json`.
  Recompute the fee estimates and policy-model costs from the completed evidence.

## Unreleased (2026-10-28): submission-candidate corrections

- Include both saved fee-sampling runs under one fixed window: 192 successful matched readings over 46.4 hours,
  covering 23 UTC hours of the day, with a 10.3-hour maximum gap. Failed readings are retained in the raw data.
- Require the independent credential-check command to exit unsuccessfully when a required verification fails.
- Include the full W3C license and per-context redistribution notices for the unchanged cached contexts.
- Describe the paper as prepared for submission until its actual submission is confirmed.
- Allow separate, labeled fee-sampling outputs; reject future Arbitrum extrapolation from receipts with nonzero
  data gas until execution gas is separated from the data component.

## v1.0.0 (2026-10-27): initial public research artifact

Code, data and analysis behind the paper prepared for IC4'27: the post circuit and the reference
RLN v2 circuit; the issuer root registry, the comparison registry with one slot per root and the on-chain posting
baseline; the client and verifier rules with their tests (49 circuit and client checks, 11 registry checks); the
benchmark, gas, revocation, fee and end-to-end measurements with their raw data; the analysis that computes every
number in the paper; the depth-20 proving and verification keys; the transaction trail with read-only checking tools;
and the independent check of the end-to-end credential.
