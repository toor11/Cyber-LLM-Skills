# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cross-site-scripting-filter-and-context-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- WAF logs showing a canonical XSS signature blocked followed by a 200 from the origin for a lexically different variant on the same parameter.
- Application responses reflecting uncommon elements or handlers such as ontoggle, onpointerenter, or <details> from user input.
- Request parameters carrying full-width, overlong, or compatibility-form characters that normalise to angle brackets.
- CSP violation reports for event-handler or inline-script blocks on routes that also pass a WAF.
- Multipart or alternate content-type requests to endpoints that normally receive urlencoded bodies, indicating a parser-differential probe.
- A burst of requests to one reflecting parameter cycling through case, encoding, and tag variations of the same token.
- Origin responses where an entity- or percent-encoded sequence appears decoded in the rendered HTML body.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
