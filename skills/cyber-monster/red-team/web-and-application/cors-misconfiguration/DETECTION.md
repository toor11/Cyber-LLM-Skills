# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cors-misconfiguration`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Reverse-proxy or application logs where Access-Control-Allow-Origin in the response equals a request Origin outside the known origin list.
- Responses that set Access-Control-Allow-Credentials: true together with a non-constant Access-Control-Allow-Origin value.
- Access-Control-Allow-Origin: null emitted for requests whose Origin header is null.
- Per-origin responses lacking a Vary: Origin header at the CDN or cache tier.
- A spike in cross-origin OPTIONS preflight requests from unfamiliar Origin values to authenticated API routes.
- Access logs showing authenticated JSON endpoints fetched with an Origin header from a newly registered or low-reputation domain.
- Configuration changes to a gateway CORS policy that introduce origin reflection or wildcard-with-credentials.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
