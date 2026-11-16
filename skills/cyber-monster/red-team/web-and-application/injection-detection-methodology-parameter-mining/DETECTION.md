# Detection Signals and Blue-Team Handoff

> Sub-skill: [`injection-detection-methodology-parameter-mining`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs where requests to one route carry rotating single undocumented parameter names from the same session.
- Framework warnings for query or body fields outside the declared schema (unpermitted parameters, unknown field).
- Requests adding override headers such as `X-Original-URL`, `X-Rewrite-URL`, or `X-Forwarded-Host` on routes that do not expect them.
- A burst of requests that differ only by one added parameter name, matching parameter-mining tool behaviour.
- User-agents of mining tools (Arjun, ParamMiner, ffuf) in access logs before injection probing begins.
- Response-size changes on a route correlated with the presence of a specific undocumented parameter.
- Candidate parameter names appearing in requests that were first seen in the site's own JavaScript bundles.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
