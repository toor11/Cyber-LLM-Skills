# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ai-application-assessment`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Model output rendered into HTML or SQL without an escaping step, visible in application logs.
- Tool credentials broader than the requesting user's role.
- Retrieval queries without a tenant filter for a multi-tenant caller.
- Prompt assembly logs where untrusted content is concatenated without a delimiter.
- Tool invocations for tools absent from the assessed surface map.
- A rise in model-driven write operations after a new tool is added.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
