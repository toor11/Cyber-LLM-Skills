# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`foundry-and-echidna-invariant-harness-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `foundry-and-echidna-invariant-harness-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Invariant run with corpus

Baseline: run with a fixed seed and no corpus. Probe: same seed with corpus persistence enabled. Differential: a failing sequence appears only when the corpus extends coverage, which shows the property is reachable.

```bash
forge test --match-contract VaultInvariant -vv --fuzz-seed 1
forge test --match-contract VaultInvariant --corpus-dir cache/inv-corpus
```

## Echidna property read

Baseline: Echidna with default config. Probe: same with a bounded actor list. Differential: a counterexample that survives both is protocol-level; one that disappears was an artefact of unbounded actors.

```bash
echidna test/Invariant.sol --contract VaultInvariant --test-limit 50000
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
