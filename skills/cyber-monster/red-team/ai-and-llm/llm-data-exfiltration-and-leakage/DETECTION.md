# Detection Signals and Blue-Team Handoff

> Sub-skill: [`llm-data-exfiltration-and-leakage`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Retrieval responses containing chunk ids whose tenant metadata differs from the caller's.
- Model answers quoting content from a document the account has never opened.
- Outbound requests to hosts not on the application's allowlist, originating from a render or fetch step on model output.
- Prompts asking the model to repeat its instructions, in logged user messages.
- A single account's query volume against documents owned by another department.
- Image or link references in model output pointing at attacker-controlled domains.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
