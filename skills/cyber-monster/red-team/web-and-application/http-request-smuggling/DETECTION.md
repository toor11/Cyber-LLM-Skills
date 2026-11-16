# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http-request-smuggling`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Reverse-proxy or origin access logs showing requests that carry both a `Content-Length` and a `Transfer-Encoding` header.
- Origin logs where one request's body bytes appear prepended to the next request line on a reused keep-alive connection.
- A sharp rise in back-end read-timeout events on POST routes while front-end request rates stay flat, consistent with framing stalls.
- Front-end 200 responses paired with origin 400 or 408 for the same connection, indicating the two parsers disagreed.
- Chunked requests whose `Transfer-Encoding` value contains leading whitespace, tabs, or a duplicate token after normalisation.
- Cache responses served to one client that contain headers or body fragments belonging to a different client's request id.
- WAF events for malformed chunk terminators or chunk extensions immediately followed by an origin 200 on the same route.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
