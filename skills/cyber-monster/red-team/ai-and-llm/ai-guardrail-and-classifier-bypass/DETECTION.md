# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ai-guardrail-and-classifier-bypass`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Requests containing encoded blobs, unusual scripts, or mixed-language text in a guardrailed endpoint.
- Guardrail block rates dropping after a client change, indicating a filter regression.
- A single account generating many near-duplicate prompts differing only in encoding.
- Output filter blocks clustered by encoding class.
- Classifier version changes without a corresponding evaluation run.
- Prompts containing instructions addressed to a classifier rather than the model.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
