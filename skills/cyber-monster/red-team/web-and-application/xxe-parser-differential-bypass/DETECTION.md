# Detection Signals and Blue-Team Handoff

> Sub-skill: [`xxe-parser-differential-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- XML request bodies whose declared encoding is UTF-16 or that begin with a byte-order mark on a parsing endpoint.
- Requests containing `xi:include` or an XInclude namespace that reach a parser after a DOCTYPE filter.
- A WAF or application filter logging a block for a UTF-8 payload followed by a 200 for the same payload re-encoded.
- Parser logs recording external entity or XInclude resolution on input a pre-check reported as clean.
- External parameter entity fetches occurring where internal entity declarations were rejected earlier in the request.
- Discrepancy alerts where a validating parser and the consuming parser log different DOCTYPE outcomes for one request.
- File-read or callback events tied to requests whose charset differs from the application's default XML encoding.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
