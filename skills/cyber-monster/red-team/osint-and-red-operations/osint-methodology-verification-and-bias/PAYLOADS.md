# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`osint-methodology-verification-and-bias`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `osint-methodology-verification-and-bias`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Independence count per claim

Baseline: total sources per claim. Probe: distinct origins per claim. Differential: a claim with one origin is single-sourced regardless of how many pages repeat it.

```bash
sqlite3 osint.db "SELECT claim, COUNT(*) AS sources, COUNT(DISTINCT origin) AS origins FROM corroboration GROUP BY claim;"
sqlite3 osint.db "SELECT claim, origin, COUNT(*) FROM corroboration GROUP BY claim, origin;"
```

## Refutation coverage

Baseline: claims with a recorded falsifier attempt. Probe: claims without one. Differential: an unattempted refutation leaves the claim unresolved.

```bash
sqlite3 osint.db "SELECT claim FROM claims WHERE falsifier_attempted = 0;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
