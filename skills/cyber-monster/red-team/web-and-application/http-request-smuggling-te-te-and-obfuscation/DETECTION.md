# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http-request-smuggling-te-te-and-obfuscation`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Origin logs recording `Transfer-Encoding` values that contain leading whitespace, duplicate tokens, or mixed case after normalisation.
- Chunk-size lines in captured requests carrying a semicolon extension on routes where no client sends extensions.
- Requests whose chunk terminators are bare line feeds rather than CRLF, flagged by a protocol-aware IDS.
- A rise in origin read-timeout events on chunked POST routes while the front-end rate is flat, consistent with a spill or starved chunk.
- Decoded chunk byte counts at the origin that disagree with the front end's recorded body length for the same request.
- Go, AIOHTTP, Traffic Server, h11, or Ktor origin error logs referencing malformed chunk extensions or trailing bytes.
- Front-end 200 paired with origin 400 for the same connection on requests that used chunked transfer encoding.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
