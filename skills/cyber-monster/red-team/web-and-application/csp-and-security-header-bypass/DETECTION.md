# Detection Signals and Blue-Team Handoff

> Sub-skill: [`csp-and-security-header-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web-server or CDN config audit where `Content-Security-Policy` contains `unsafe-inline` or `unsafe-eval` on `script-src`.
- Responses where the CSP `nonce-` value repeats across requests to the same route within a log window.
- CSP `report-uri` or `report-to` endpoints receiving violation reports naming `base-uri`, `object-src`, or `form-action`.
- Access logs showing POSTs whose form-action target is an external host on a page that handles credentials.
- Security-header scanners flagging absent `base-uri`, `object-src`, or `frame-ancestors` on authenticated routes.
- Requests loading scripts from an allowlisted origin's JSONP or callback path with an attacker-controlled callback parameter.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
