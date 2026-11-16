# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ml-adversarial-and-data-poisoning`](SKILL.md) | Family: **AI and LLM**

Probes for `ml-adversarial-and-data-poisoning`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Paired perturbation

Baseline: the clean prediction. Probe: the prediction for the perturbed input. Differential: a label change at a small magnitude, with the clean prediction stable across repeats.

```python
clean = model.predict(case.input)
perturbed = model.predict(perturb(case.input, eps=0.03))
print(clean.label, perturbed.label, clean.confidence, perturbed.confidence)
```

## Trigger behaviour check

Baseline: the output for inputs without the trigger. Probe: the same inputs with the trigger appended. Differential: a consistent output shift only for triggered inputs is the backdoor signature.

```bash
python -c "import json; r=json.load(open('trigger-eval.json')); print(sum(1 for x in r['cases'] if x['with_trigger'] != x['without_trigger']))"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
