# Detection Signals and Blue-Team Handoff

> Sub-skill: [`race-conditions-and-concurrency-single-packet-attack`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Origin access logs with twenty or more requests on one HTTP/2 connection inside a sub-millisecond window.
- Identical paths or request ids arriving in one stream group on a single connection.
- CDN or WAF metrics showing a single connection carrying an abnormal concurrent-stream count.
- Packet captures where many stream last-bytes land in one TCP segment.
- A burst of same-route POSTs with near-zero inter-arrival delta from one client.
- Proxy logs showing pipelined HTTP/1.1 requests released together on one keep-alive connection.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
