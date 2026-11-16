# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ai-guardrail-and-classifier-bypass`](SKILL.md) | Family: **AI and LLM**

Probes for `ai-guardrail-and-classifier-bypass`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Encoding-class parity

Baseline: the plain form is blocked. Probe: the encoded form carries the same request. Differential: an allowed encoded form with a blocked plain form is the bypass.

```bash
python -c "import json; print(json.load(open('verdicts.json'))['cases'])"
python -c "import base64; print(base64.b64encode(b'blocked request').decode())"
```

## Threshold sensitivity

Baseline: the classifier score for the blocked form. Probe: the score for a paraphrase. Differential: a paraphrase below the threshold with the same meaning is the bypass.

```bash
python -c "import json; r=json.load(open('scores.json')); print(r['blocked'], r['paraphrase'], r['threshold'])"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
