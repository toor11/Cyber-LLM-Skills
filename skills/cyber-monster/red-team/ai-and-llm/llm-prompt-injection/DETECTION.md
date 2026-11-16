# Detection Signals and Blue-Team Handoff

> Sub-skill: [`llm-prompt-injection`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Prompts containing imperatives addressed to the model inside retrieved content, visible in the logged context.
- Tool invocations for tools unrelated to the user's stated task.
- A sharp rise in a tool's call rate after a document ingestion job.
- Model output that contains instruction-like text echoed into a user-facing field.
- Context length jumps correlated with a document upload, indicating content concatenation.
- Repeated requests with near-identical context and a single appended instruction line.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-and-llm-application-defense`](../../../blue-team/application-security/ai-and-llm-application-defense/SKILL.md) | Query authoring, triage, and hardening |
