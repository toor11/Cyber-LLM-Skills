# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http-request-smuggling-client-side-desync`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs where a GET or HEAD request carried a non-zero `Content-Length` and still returned 200 on a keep-alive connection.
- Sequential requests on one connection id where the second request's path does not match any `Referer` or expected navigation.
- Browser-origin connections that remain open after the server received a body on a method that should not carry one.
- Follow-up requests whose captured headers or body appear reflected in an unrelated response served on the same socket.
- A rise in requests to attacker-chosen in-scope paths that correlate with cross-origin navigations from external referrers.
- Edge logs showing HTTP/1.1 connection reuse to the origin where HTTP/2 was expected for browser clients.
- Repeated priming-then-navigation patterns from a single client ip against endpoints that accept unexpected bodies.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
