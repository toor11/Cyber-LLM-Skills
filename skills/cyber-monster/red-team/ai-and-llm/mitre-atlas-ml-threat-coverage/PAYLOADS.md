# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`mitre-atlas-ml-threat-coverage`](SKILL.md) | Family: **AI and LLM**

Probes for `mitre-atlas-ml-threat-coverage`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Matrix completeness

Baseline: techniques in scope. Probe: techniques with an observable and a control. Differential: a technique with neither belongs in the gap list, not in the covered set.

```bash
jq '.rows | length' atlas-map.json
jq '.gaps | length' atlas-map.json
jq '[.rows[] | select(.observable != null)] | length' atlas-map.json
```

## Observable verification

Baseline: the observable claimed for a technique. Probe: a query proving telemetry exists. Differential: a claimed observable with no events cannot support any coverage claim.

```bash
python -c "import yaml; m=yaml.safe_load(open('atlas-map.yaml')); print([r['observable'] for r in m['rows']][:3])"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
