# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`osint-methodology-collection-and-logging`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `osint-methodology-collection-and-logging`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Schema completeness query

Baseline: rows written. Probe: rows missing a required provenance field. Differential: any incomplete row indicates a write path that bypassed the schema.

```bash
sqlite3 osint.db "SELECT COUNT(*) FROM log;"
sqlite3 osint.db "SELECT COUNT(*) FROM log WHERE analyst IS NULL OR source IS NULL OR query IS NULL OR fetched_at IS NULL;"
sqlite3 osint.db "SELECT analyst, COUNT(*) FROM log GROUP BY analyst;"
```

## Re-retrieval hash comparison

Baseline: the stored hash. Probe: the hash from a fresh retrieval. Differential: a difference means the source is mutable and both observations must be kept.

```bash
sqlite3 osint.db "SELECT raw_sha256 FROM log WHERE source='rdap' ORDER BY id DESC LIMIT 1;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
