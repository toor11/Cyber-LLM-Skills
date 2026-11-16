# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-cache-poisoning-and-deception-unkeyed-input`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Cache logs where a response served with `X-Cache: HIT` contains a value from `X-Forwarded-Host`, `X-Forwarded-Scheme`, or `X-Forwarded-For`.
- Redirect `Location` headers whose host or scheme differs from the site's canonical values on a cacheable route.
- Duplicate query parameters recorded at the origin where only one copy appears in the CDN key.
- GET requests carrying a request body (fat GET) to a cacheable endpoint.
- Missing `Vary` headers on responses that reflect forwarded headers, recorded at the origin.
- A clean request receiving body content that matches a value only ever sent by a prior request's header.
- `Age` advancing on a URL whose response body includes host or scheme values from request headers.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
