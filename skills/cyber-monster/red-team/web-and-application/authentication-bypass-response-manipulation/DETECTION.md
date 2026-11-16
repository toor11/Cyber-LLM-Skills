# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authentication-bypass-response-manipulation`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Responses with HTTP 401 or 403 whose body length matches the authenticated 200 body for the same route.
- Deny-status responses whose JSON body contains populated user, dashboard, or balance fields.
- Client error telemetry showing navigation to privileged views after a failed authentication call.
- Proxy logs where status rewriting or match-and-replace patterns appear within a session.
- Repeated requests to the same protected endpoint with identical bodies under valid and missing credentials.
- Mobile or single-page-app backends returning authenticated:false alongside a non-empty protected payload.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
