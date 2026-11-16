# Detection Signals and Blue-Team Handoff

> Sub-skill: [`agentic-ai-and-mcp-security`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Tool invocations whose destination argument differs from the user's stated intent in the same session.
- A tool call immediately following the ingestion of external content into the context.
- MCP server connection to an endpoint whose identity differs from the approved one.
- Bursts of tool calls from one session with escalating side effects (read, then write, then transfer).
- Service-account credentials used for actions attributed to an individual user.
- New tool descriptions appearing after a server re-connect, without a client-side change.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`llm-input-output-guardrail-middleware-development`](../../../blue-team/security-automation-and-tool-development/llm-input-output-guardrail-middleware-development/SKILL.md) | Query authoring, triage, and hardening |
