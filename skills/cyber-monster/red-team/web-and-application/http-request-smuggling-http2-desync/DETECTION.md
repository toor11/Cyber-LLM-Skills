# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http-request-smuggling-http2-desync`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Edge logs showing HTTP/2 negotiated with clients while the origin connection is HTTP/1.1 for the same request.
- Downgraded origin requests whose `content-length` equals a client-supplied value rather than the counted DATA bytes.
- A surviving `transfer-encoding: chunked` header on origin requests that originated as HTTP/2.
- Origin requests containing a second request line that the front end never logged as a separate stream.
- HTTP/2 header or pseudo-header values containing CRLF sequences flagged by a protocol-aware filter.
- Origin read-timeout events correlated with HTTP/2 streams whose DATA length and content-length disagreed.
- Front-end stream-error counters for duplicate or malformed pseudo-headers rising alongside origin framing errors.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
