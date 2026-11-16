# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cross-site-scripting`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Response bodies where a request parameter is reflected with unencoded < or > on an HTML content type.
- CSP violation reports (report-uri or report-to) citing inline-script or event-handler blocks on user-facing routes.
- Stored fields later served to other users that contain script tags, on or event-handler attributes, or javascript: URLs.
- Browser telemetry or RUM showing script errors referencing injected attribute names on pages that render user content.
- WAF hits for XSS signatures followed by a 200 from the origin on the same reflecting route.
- Set-Cookie for the session issued without HttpOnly on applications that render user-supplied HTML.
- Outbound requests from user browsers to an unfamiliar collector host immediately after loading a page with stored user content.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
