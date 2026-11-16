# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http-parameter-pollution-and-mass-assignment`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application update events where a persisted `role`, `is_staff`, `tenant_id`, or `price` field changed on a request whose documented form never submits it.
- Framework logs recording bound parameters that are not in the model's permitted or serializer field set (Rails `Unpermitted parameters`, DRF unknown field warnings).
- Requests containing the same parameter name more than once, or array and scalar forms of one key, on routes that expect a single value.
- A mismatch between the parameter value a WAF logged for a rule decision and the value the application access log recorded for the same request id.
- JSON request bodies accepted with keys outside the published schema on API gateways that log request shape.
- Audit entries where an ownership or lifecycle field (`owner_id`, `created_at`, `verified`) was modified through a general profile or settings endpoint.
- Spikes in 200 responses to update routes immediately after parameter-mining tooling user-agents appear in access logs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
