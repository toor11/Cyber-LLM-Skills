# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`osint-methodology`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `osint-methodology`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Provenance coverage check

Baseline: the number of observations collected. Probe: the number with complete provenance. Differential: any observation missing source, timestamp, or hash cannot enter the report.

```bash
sqlite3 osint.db "SELECT COUNT(*) FROM obs;"
sqlite3 osint.db "SELECT COUNT(*) FROM obs WHERE source IS NULL OR fetched_at IS NULL OR raw_sha256 IS NULL;"
sqlite3 osint.db "SELECT source, COUNT(*) FROM obs GROUP BY source ORDER BY 2 DESC;"
```

## Hypothesis ledger

Baseline: hypotheses with no supporting observation. Probe: hypotheses with both supporting and refuting observations. Differential: a hypothesis supported only by confirming evidence is unresolved, not proven.

```bash
sqlite3 osint.db "SELECT hypothesis, COUNT(*) FILTER (WHERE stance='supports') AS s, COUNT(*) FILTER (WHERE stance='refutes') AS r FROM evidence GROUP BY hypothesis;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
