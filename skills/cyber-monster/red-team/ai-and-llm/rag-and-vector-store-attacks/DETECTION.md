# Detection Signals and Blue-Team Handoff

> Sub-skill: [`rag-and-vector-store-attacks`](SKILL.md) | Family: **AI and LLM**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Retrieval requests whose filter field is absent or empty for a multi-tenant caller.
- Ingestion API calls from a principal that has no write permission in the identity store.
- A sudden increase in retrieved chunks from one source document across many users.
- Vector store queries returning hits with a tenant metadata value different from the caller's.
- Embedding requests for the same document repeated many times in a short window, characteristic of ranking manipulation attempts.
- Context assembly logs where chunk boundaries are absent, complicating injection detection.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ai-agent-and-llm-telemetry-hunting`](../../../blue-team/threat-intelligence-and-hunting/ai-agent-and-llm-telemetry-hunting/SKILL.md) | Query authoring, triage, and hardening |
