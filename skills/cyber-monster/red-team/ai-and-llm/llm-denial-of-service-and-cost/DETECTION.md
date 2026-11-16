# Detection Signals and Blue-Team Handoff

> Sub-skill: [`llm-denial-of-service-and-cost`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Requests with `max_tokens` set to the provider maximum from accounts with no history.
- A single account's token consumption exceeding the per-account baseline by an order of magnitude.
- Agent sessions with a step count far above the median.
- Context lengths near the model's limit arriving from one client.
- Repeated identical requests in a short window, characteristic of a cost amplification attempt.
- Quota rejections concentrated on one account, indicating an attempt rather than organic usage.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
