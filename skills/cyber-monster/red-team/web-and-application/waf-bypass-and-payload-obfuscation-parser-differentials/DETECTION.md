# Detection Signals and Blue-Team Handoff

> Sub-skill: [`waf-bypass-and-payload-obfuscation-parser-differentials`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WAF logs where a POST is blocked under `application/x-www-form-urlencoded` but the same route returns origin 200 for `multipart/form-data` from one session.
- Requests carrying a `charset=` parameter other than utf-8 (for example ibm037) on form submissions, in the proxy access log.
- Origin framework logs listing a parameter value absent from the upstream WAF request log for the matching request id.
- POST bodies with `Transfer-Encoding: chunked` reaching an origin behind a WAF that logs only a content length.
- Duplicate parameter names in a single query string or body recorded by the application router.
- A measurable drop in WAF rule-hit rate on an endpoint coinciding with a rise in non-standard content types.
- Multipart requests whose boundary token appears doubled or quoted in the raw body capture.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
