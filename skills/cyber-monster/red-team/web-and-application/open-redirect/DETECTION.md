# Detection Signals and Blue-Team Handoff

> Sub-skill: [`open-redirect`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- HTTP 301/302 responses where the Location header host differs from the application's own domain on the login or logout route.
- Access logs where the next, returnUrl, or redirect parameter carries an absolute URL, a `//` prefix, or a backslash.
- Referer headers on outbound navigations pointing from the application's redirect endpoint to an unrelated external host.
- A single session issuing repeated requests to one redirect route while cycling through many distinct target hosts.
- Set-Cookie or Authorization values appearing in requests to the external host named by a prior Location header.
- WAF redirect-rule hits immediately followed by a 302 from the origin on the same route.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
