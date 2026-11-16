# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cross-site-scripting-blind-and-oob-xss`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Outbound requests from an internal admin or reporting host to an external collector domain shortly after an operator opens a record.
- CSP violation reports originating from an administrative console URL rather than a public page.
- Server-side renderer processes (headless Chromium, wkhtmltopdf) making network connections to unfamiliar hosts during report generation.
- Stored fields such as User-Agent, referer, or filename containing script tags or on-event attributes in the database.
- Admin-portal access logs correlating a record view with a near-simultaneous external callback carrying a matching identifier.
- DNS queries from the internal network for freshly registered callback domains embedded in stored user content.
- A surge of submissions to feedback, ticket, or profile fields that each carry a distinct external URL.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
