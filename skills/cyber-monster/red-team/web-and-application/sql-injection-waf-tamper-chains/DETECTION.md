# Detection Signals and Blue-Team Handoff

> Sub-skill: [`sql-injection-waf-tamper-chains`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WAF logs showing a 403 for a payload immediately followed by an origin 200 for a near-identical request from the same source.
- Requests to one route where the same parameter appears both urlencoded and as multipart form-data within a session.
- Query logs at the origin containing SQL keywords the WAF ruleset is configured to block.
- Bursts of requests cycling through comment, case, and encoding variants of one base payload.
- Content-Type header switching between application/x-www-form-urlencoded and multipart/form-data on the same endpoint.
- Unicode full-width or best-fit characters in parameters that normalise to quotes or keywords at the application.
- WAF rule-hit counts dropping while origin database error rates rise on the same route.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`secure-code-review-injection-and-data-flow`](../../../blue-team/application-security/secure-code-review-injection-and-data-flow/SKILL.md) | Detection queries, triage, and hardening for this technique |
