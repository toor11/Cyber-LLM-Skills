# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`llm-output-handling-and-sinks`](SKILL.md) | Family: **AI and LLM**

Probes for `llm-output-handling-and-sinks`. Each group names the baseline it is compared against and the differential that counts. Run every probe twice; a one-off difference is not proof.

## Render sink probe

Baseline: benign output renders as text. Probe: output containing a script tag renders escaped. Differential: an executed tag means no escaping at the sink.

```text
Baseline output: 'Total revenue was 4% higher.'
Probe output: 'Total revenue was <script>alert(1)</script> higher.'
Inspect: rendered DOM versus the raw model response
```

## Query sink probe

Baseline: a model output with no metacharacters returns one row. Probe: output containing a quote changes the result set. Differential: a changed result set indicates interpolation rather than binding.

```bash
python -c "import sqlite3; c=sqlite3.connect(':memory:'); print(c.execute('select ?', (\"it's\",)).fetchall())"
```

## Usage Rules

- Baseline first, probe second, same scope and same credentials for both runs.
- Stop at the first confirmed differential; do not expand the probe once it fires.
- Pair every confirmed finding with the structural remediation in [`SKILL.md`](SKILL.md).
