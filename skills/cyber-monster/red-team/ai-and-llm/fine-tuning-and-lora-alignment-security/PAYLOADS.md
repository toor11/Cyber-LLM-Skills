# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`fine-tuning-and-lora-alignment-security`](SKILL.md) | Family: **AI and LLM**

Probes for `fine-tuning-and-lora-alignment-security`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Base versus trained evaluation

Baseline: refusal behaviour from the base model. Probe: the same cases against the trained artefact. Differential: a case refused by the base and answered by the trained model is a regression.

```bash
python -c "import json; b=json.load(open('eval-base.json')); t=json.load(open('eval-tuned.json')); print([k for k in b if b[k] != t.get(k)])"
jq '[.cases[] | select(.refused == true)] | length' eval-base.json
jq '[.cases[] | select(.refused == true)] | length' eval-tuned.json
```

## Canary extraction

Baseline: the canary string must not appear in outputs. Probe: prompts designed to elicit memorised content. Differential: the canary appearing in output proves the training data was retained.

```bash
python -c "import json; r=json.load(open('canary-probe.json')); print(any('CANARY-9f2c' in x for x in r['outputs']))"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
