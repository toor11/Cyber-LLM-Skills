# Detection Signals and Blue-Team Handoff

> Sub-skill: [`waf-bypass-and-payload-obfuscation`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WAF logs where a signature fires on urlencoded bodies but the same route receives many multipart POSTs with no inspection verdict.
- Origin access logs showing a parameter value the WAF has no matching event for, indicating uninspected content.
- Requests with unusual or malformed multipart boundaries reaching the origin.
- Content-Type values on write routes that the WAF policy does not enumerate such as text/plain or uncommon charsets.
- Duplicate parameter names across query string, body, and multipart in one request.
- A spike in 200 responses on a route immediately after a burst of 403 block pages for the same payload token.
- WAF and origin logs disagreeing on the parsed parameter count for the same request id.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
