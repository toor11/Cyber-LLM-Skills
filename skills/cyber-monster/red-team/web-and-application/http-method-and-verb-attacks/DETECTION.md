# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http-method-and-verb-attacks`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs with `X-HTTP-Method-Override`, `X-Method-Override`, or a `_method` field altering the effective verb.
- Requests using uncommon verbs (PUT, PATCH, DELETE, TRACE, or custom methods) on routes normally driven by GET or POST.
- State-changing responses to GET requests on account or admin routes.
- TRACE requests returning request headers in the response body.
- OPTIONS responses whose `Allow` header lists more methods than the application documents.
- Proxy and origin logs disagreeing on the method recorded for the same request id.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
