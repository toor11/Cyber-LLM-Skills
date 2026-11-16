# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`physical-and-facility-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `physical-and-facility-osint`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Occupancy at an address

Baseline: the target entity at the address. Probe: all entities at the address. Differential: additional occupants change the site description.

```bash
curl -sS 'https://registry.example/search?address=AB1%202CD' | jq '.results[].name'
curl -sS 'https://registry.example/search?address=AB1%202CD' | jq '.results | length'
```

## Permit history

Baseline: the current use recorded in the register. Probe: the planning record. Differential: a change of use after the register entry explains a structural difference in the imagery.

```bash
curl -sS 'https://planning.example/search?postcode=AB1%202CD' | jq '.results[] | {reference, decision_date, description}'
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
