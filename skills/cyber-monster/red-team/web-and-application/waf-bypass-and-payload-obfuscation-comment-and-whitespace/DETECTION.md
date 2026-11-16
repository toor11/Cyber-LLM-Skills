# Detection Signals and Blue-Team Handoff

> Sub-skill: [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WAF logs where a keyword rule fires on a contiguous UNION SELECT but the same route receives a comment-split form with no block event.
- Origin query logs containing SQL comments inside parameter values.
- Requests where parameters contain newline, tab, or form feed percent-encodings between SQL keywords.
- Database error or slow-query logs reconstructing a keyword that arrived split in the HTTP request.
- A 403-then-200 sequence for the same parameter differing only by inserted comments.
- ModSecurity audit entries where the normalized and raw argument differ by comment removal.
- Spikes in versioned-comment patterns such as a slash-bang block on routes that reach a MySQL backend.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
