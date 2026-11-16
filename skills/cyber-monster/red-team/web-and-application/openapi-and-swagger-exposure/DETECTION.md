# Detection Signals and Blue-Team Handoff

> Sub-skill: [`openapi-and-swagger-exposure`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access-log hits on /v3/api-docs, /openapi.json, /swagger.json, or /swagger-ui from unauthenticated sources.
- A single client requesting many enumerated operation paths within seconds after fetching the spec document.
- Responses on a production host with Content-Type application/json whose body begins with an openapi or swagger version field.
- User-Agent strings of schema scrapers or API fuzzers against the documentation paths.
- First-time requests to deprecated or internal operations that only appear in the published specification.
- swagger-ui requests carrying a url or configUrl query parameter pointing at an external host.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
