# Detection Signals and Blue-Team Handoff

> Sub-skill: [`llm-jailbreak-and-guardrails`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Prompt patterns containing role-play framing, encoding directives, or instructions to disregard prior context, in logged requests.
- A rising rate of refusals followed by retries with rephrased prompts from one account.
- Output filter blocks clustered on one user or session.
- Requests with unusually long conversational preambles before the operative instruction.
- Model responses that pass the filter but contain policy-relevant content, visible in output sampling.
- Rapid model-version probing, such as repeated requests with a version parameter changed.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
