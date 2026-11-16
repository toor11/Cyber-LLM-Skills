# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http2-specific-attacks`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- HTTP/2 connections with a RST_STREAM-to-stream-completion ratio far above normal, especially server-initiated resets.
- Backend worker concurrency metrics exceeding the server's advertised `SETTINGS_MAX_CONCURRENT_STREAMS` for a single connection.
- Tomcat, netty, or F5 BIG-IP logs showing bursts of stream resets correlated with CPU or thread-pool saturation.
- A spike in RST_STREAM frames shortly after HEADERS on many streams of one connection, the Rapid Reset signature.
- `Upgrade: h2c` requests accepted with a 101 response on connections the front end expected to mediate.
- Pseudo-header validation errors (`:path`, `:authority`) rising in the HTTP/2 frame layer logs.
- Connection-level counters where streams are freed from the active count while their backend requests are still in flight.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
