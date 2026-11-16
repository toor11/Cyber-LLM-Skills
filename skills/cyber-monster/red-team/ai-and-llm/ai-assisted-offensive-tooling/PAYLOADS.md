# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ai-assisted-offensive-tooling`](SKILL.md) | Family: **AI and LLM**

Probes for `ai-assisted-offensive-tooling`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Claim verification

Baseline: the model's claim about a specific vulnerability. Probe: the vendor advisory for that product and version. Differential: a claim the advisory does not support is dropped before delivery.

```text
Claim: 'CVE-2026-0000 affects product X version 2.1'
Check: vendor advisory for product X, affected version range
Record: applicable / not applicable, and the advisory URL
```

## Generated payload review

Baseline: the probe the analyst intended. Probe: the model's generated variant. Differential: any element that widens scope or changes state is removed before execution.

```bash
python -c "import json; print(json.load(open('assist-log.json'))['entries'][-1]['payload'])"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
