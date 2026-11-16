# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`osint-collector-and-entity-graph-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Probes for `osint-collector-and-entity-graph-scripting`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Provenance round trip

Baseline: the stored hash of a record at first retrieval. Probe: the hash at second retrieval. Differential: a hash change means the source is mutable and both observations must be retained.

```bash
sqlite3 osint.db "SELECT id, source, fetched_at, raw_sha256 FROM obs ORDER BY id DESC LIMIT 5;"
sqlite3 osint.db "SELECT COUNT(DISTINCT raw_sha256), COUNT(*) FROM obs;"
sqlite3 osint.db "SELECT source, COUNT(*) FROM obs GROUP BY source;"
```

## Weak-edge review query

Baseline: strong edges from exact identifiers. Probe: weak edges from name similarity. Differential: weak edges need a second identifier before entering the strong graph.

```bash
sqlite3 osint.db "SELECT COUNT(*) FROM edge_strong;"
sqlite3 osint.db "SELECT COUNT(*) FROM edge_weak;"
sqlite3 osint.db "SELECT * FROM edge_weak LIMIT 5;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
