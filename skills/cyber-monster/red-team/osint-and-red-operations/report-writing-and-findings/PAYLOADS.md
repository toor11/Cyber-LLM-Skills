# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`report-writing-and-findings`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `report-writing-and-findings`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Baseline versus probe pair

Baseline: the request with the caller's own object id. Probe: the same request with a foreign id. Differential: a 200 with foreign data is the finding; a 404 means the control holds.

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $A" https://api.client.example/v2/invoices/A
curl -sS -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $A" https://api.client.example/v2/invoices/B
```

## Template completeness

Baseline: findings with all required fields. Probe: findings missing a reproduction. Differential: an incomplete finding cannot be triaged and must not ship.

```bash
python -c "import yaml; f=yaml.safe_load(open('finding.yaml')); print([k for k in ('title','location','invariant','baseline','probe','impact','remediation') if not f.get(k)])"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
