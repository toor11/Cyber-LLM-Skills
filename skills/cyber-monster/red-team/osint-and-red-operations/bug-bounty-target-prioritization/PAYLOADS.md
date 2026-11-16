# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`bug-bounty-target-prioritization`](SKILL.md) | Family: **OSINT and Red Operations**

Probes for `bug-bounty-target-prioritization`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Policy extract

Baseline: the programme page summary. Probe: the policy text's scope and exclusions. Differential: an excluded class changes the priority regardless of severity.

```bash
python -c "import yaml; d=yaml.safe_load(open('programme.yaml')); print(d['scope'], d['exclusions'], d['retrieved_at'])"
python -c "import yaml; d=yaml.safe_load(open('programme.yaml')); print(d['severity'])"
```

## Change signal check

Baseline: documented public endpoints. Probe: endpoints referenced in release notes or a new API version. Differential: an endpoint documented but not in the public client is fresh surface.

```bash
curl -sS https://api.client.example/v3/openapi.json | jq '.paths | keys | length'
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
