# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`smart-contract-audit-testing-and-invariants`](SKILL.md) | Family: **Blockchain**

Probes for `smart-contract-audit-testing-and-invariants`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Invariant campaign with corpus

Baseline: a fixed-seed run without corpus. Probe: the same seed with corpus persistence. Differential: a failing sequence that appears only with coverage extension shows the property is reachable.

```bash
forge test --match-contract Props -vv --fuzz-seed 1
forge test --match-contract Props --corpus-dir cache/inv-corpus
```

## Fork test at a pinned block

Baseline: the deployed behaviour at block N. Probe: the same test after the candidate change. Differential: a failure only in the probe is the finding.

```bash
forge test --match-test testDeployedBehaviour --fork-url $RPC --fork-block-number 19000000 -vvv
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
