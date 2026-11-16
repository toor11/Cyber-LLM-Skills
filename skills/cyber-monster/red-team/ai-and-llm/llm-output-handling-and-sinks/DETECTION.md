# Detection Signals and Blue-Team Handoff

> Sub-skill: [`llm-output-handling-and-sinks`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Model output stored and later rendered into HTML without an escaping step.
- Database queries built with string concatenation around a model-derived value.
- Subprocess calls with `shell=True` and a model-derived argument.
- Links generated from model output without a scheme allowlist.
- Stored model responses appearing in other users' rendered pages.
- A CSP report spike after a model-driven feature launch.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
