# Changelog

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
