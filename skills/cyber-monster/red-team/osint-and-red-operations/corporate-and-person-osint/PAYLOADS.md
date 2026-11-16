# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`corporate-and-person-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `corporate-and-person-osint`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Convention confirmation

Baseline: one published address. Probe: a second from an independent publication. Differential: both matching the same format confirms the convention; a mismatch means the scheme is unknown.

```bash
sqlite3 osint.db "SELECT address, source, published_at FROM addresses WHERE verified=1;"
sqlite3 osint.db "SELECT address, source, published_at FROM addresses ORDER BY published_at DESC LIMIT 5;"
```

## Role versus identity source check

Baseline: records with a role source. Probe: the same records with an identity source. Differential: a role with no identity source is an unattributed title, not a person record.

```bash
sqlite3 osint.db "SELECT person, role_source, identity_source FROM people WHERE identity_source IS NULL;"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
