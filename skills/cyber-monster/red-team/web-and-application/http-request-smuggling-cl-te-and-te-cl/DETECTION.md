# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http-request-smuggling-cl-te-and-te-cl`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Origin access logs where a POST request's trailing bytes appear as a new request line on a reused keep-alive connection.
- Requests logged at both tiers carrying `Content-Length` and `Transfer-Encoding: chunked` together.
- A rise in origin read-timeout or 408 events on POST routes while the front-end request rate is unchanged.
- Front-end 200 responses matched with origin 400 or 408 for the same connection identifier, showing a framing split.
- Chunked POST bodies whose declared `Content-Length` does not equal the decoded chunk byte count.
- OPTIONS requests containing obsolete line-folding continuation lines alongside an `Expect: 100-continue` header.
- Proxy error logs from Rust-based edges (Pingora class) referencing inconsistent body length on upstream forwarding.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
