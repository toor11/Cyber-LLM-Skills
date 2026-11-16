# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`company-registry-and-beneficial-ownership-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `company-registry-and-beneficial-ownership-osint`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Entity resolution

Baseline: the registration number. Probe: the LEI record for the same entity. Differential: a matching LEI confirms the global identifier; a mismatch means two different entities share a name.

```bash
curl -sS 'https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=Target%20Holdings' | jq '.data[].attributes.entity'
jq '.data[] | {lei: .attributes.lei, status: .attributes.registration.status}' lei.json
```

## Officer change over time

Baseline: the current officer list. Probe: filings from an earlier period. Differential: an appointment or resignation between the dates is the control-relevant change.

```bash
curl -sS https://rdap.example/entity/01234567 | jq '.entities[] | {handle, roles}'
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
