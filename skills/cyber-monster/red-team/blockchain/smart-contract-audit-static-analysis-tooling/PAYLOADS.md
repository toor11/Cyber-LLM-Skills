# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`smart-contract-audit-static-analysis-tooling`](SKILL.md) | Family: **Blockchain**

Probes for `smart-contract-audit-static-analysis-tooling`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Scoped run with JSON output

Baseline: the unfiltered run's detector count. Probe: the scoped run's count. Differential: the difference is dependency and test code, which is out of scope.

```bash
slither . --json all.json
slither . --filter-paths 'test|script|lib' --exclude-dependencies --json scoped.json
jq '.results.detectors | length' scoped.json
```

## Reachability check

Baseline: the detector's location. Probe: the caller set for that function. Differential: no external caller means the item is a note, not a finding.

```bash
forge inspect Bank abi --json | jq '[.[] | select(.type=="function") | .name]'
slither . --print call-graph --filter-paths 'lib' | head -40
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
