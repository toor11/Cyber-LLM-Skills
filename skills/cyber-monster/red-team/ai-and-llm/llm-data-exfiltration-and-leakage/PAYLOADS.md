# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`llm-data-exfiltration-and-leakage`](SKILL.md) | Family: **AI and LLM**

Probes for `llm-data-exfiltration-and-leakage`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Two-account retrieval

Baseline: account A's answer with its retrieved chunk ids. Probe: the same query under account B. Differential: any chunk id from the other tenant, or an answer containing its content, is the leak.

```bash
python -c "import json; print(json.load(open('answer-a.json'))['chunk_ids'])"
python -c "import json; print(json.load(open('answer-b.json'))['chunk_ids'])"
```

## Outbound reference check

Baseline: the answer's URLs against the allowlist. Probe: an answer induced to contain a non-allowlisted host. Differential: a fetched non-allowlisted URL indicates an exfiltration channel.

```bash
python -c "import json,re; a=json.load(open('answer.json')); print(re.findall(r'https?://[^ ]+', a['text']))"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
