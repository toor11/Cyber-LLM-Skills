# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`llm-denial-of-service-and-cost`](SKILL.md) | Family: **AI and LLM**

Probes for `llm-denial-of-service-and-cost`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Worst-case request cost

Baseline: the median request's token usage. Probe: a request at every user-controlled maximum. Differential: a cost multiple above the quota's assumption is the amplification.

```bash
python -c "import json; print(json.load(open('usage-median.json'))['total_tokens'], json.load(open('usage-max.json'))['total_tokens'])"
jq '.usage.total_tokens' usage-max.json
jq '.usage.total_tokens' usage-median.json
```

## Loop bound check

Baseline: a normal request completes in one step. Probe: a request that induces repeated tool calls. Differential: unbounded steps indicate the loop termination depends on model output.

```bash
python -c "import json; print(json.load(open('loop.json'))['steps'])"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
