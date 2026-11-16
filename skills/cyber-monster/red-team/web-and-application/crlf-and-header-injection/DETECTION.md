# Detection Signals and Blue-Team Handoff

> Sub-skill: [`crlf-and-header-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web server access logs where a request parameter contains %0d%0a, %0a, or raw CR/LF before a redirect or cookie-setting route.
- Response captures showing an unexpected header such as an attacker-named X- header or a second Set-Cookie on a route that sets one cookie.
- Application logs with records split across lines where a single request produced two timestamps or two log levels.
- WAF signatures for CRLF or response-splitting patterns followed by a 200 or 302 from the origin.
- Cache or CDN logs showing a cached response whose header block differs from the origin's canonical headers for that path.
- Redirect responses whose Location header contains embedded newlines or an injected second header name.
- A rise in requests to language, redirect, or tracking parameters carrying encoded control characters.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
