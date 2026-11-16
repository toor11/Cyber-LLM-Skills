# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-cache-poisoning-and-deception`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- CDN logs showing `X-Cache: HIT` served to many clients for a URL whose body contains a value from a request header.
- Responses where `Cache-Control: public` is set on a path that also returns per-user data fields.
- A spike in `Age` resets on one keyed URL indicating repeated store operations from a single source.
- Requests with mismatched `Host` and `X-Forwarded-Host` headers reaching a cacheable route.
- Authenticated routes served with `cf-cache-status: HIT` or `X-Cache: HIT` in the edge log.
- Access logs where one path is requested with and without a trailing static extension in quick succession.
- Missing or overly broad `Vary` headers on responses that reflect request headers, recorded at the origin.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
