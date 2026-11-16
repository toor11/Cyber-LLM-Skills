# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`infrastructure-osint-dns-and-certificate`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `infrastructure-osint-dns-and-certificate`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Historical versus authoritative

Baseline: the passive DNS record with its timestamps. Probe: the authoritative answer now. Differential: NXDOMAIN or a different address makes the record historical only.

```bash
dig +short old.target.example @1.1.1.1
dig +trace old.target.example | tail -20
```

## Wildcard check

Baseline: a random label under the zone. Probe: a known name in the zone. Differential: both resolving identically indicates a wildcard, invalidating enumeration results.

```bash
dig +short $(openssl rand -hex 6).target.example
dig +short www.target.example
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
