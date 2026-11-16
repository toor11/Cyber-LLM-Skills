# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ai-supply-chain-and-plugin-risk`](SKILL.md) | Family: **AI and LLM**

Probes for `ai-supply-chain-and-plugin-risk`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Scope comparison

Baseline: the requesting user's scopes. Probe: the plugin credential's scopes. Differential: a plugin scope with no user counterpart is the escalation.

```bash
python -c "import yaml; p=yaml.safe_load(open('plugins.yaml'))['plugins'][0]; print(p['credential'])"
python -c "import json; print(json.load(open('user-scopes.json'))['scopes'])"
```

## Manifest pin check

Baseline: the pinned hash. Probe: the hash of the manifest served now. Differential: a mismatch means the approved component changed.

```bash
curl -sS https://plugins.example/crm/manifest.json | sha256sum
python -c "import yaml; print(yaml.safe_load(open('plugins.yaml'))['plugins'][0]['manifest_sha256'])"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
