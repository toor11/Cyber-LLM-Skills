# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cross-site-scripting-stored`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Application logs where a stored field (comment, display_name, filename) is written containing angle brackets or a quote and later served on a different route.
- Response bodies on list, detail, or dashboard routes whose length increased after a specific record was created and that contain tag characters from that record.
- CSP `report-uri` or `report-to` violations citing inline `script-src` on an authenticated dashboard route rather than a public page.
- Database or ORM audit entries showing a text column stored with raw HTML markup that a render template later emits.
- Admin-session RUM telemetry reporting unexpected DOM nodes on a moderation page.
- A single low-privilege account writing to a field that is then fetched by an admin session within minutes.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
