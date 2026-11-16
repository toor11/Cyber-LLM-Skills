# Detection Signals and Blue-Team Handoff

> Sub-skill: [`clickjacking-and-ui-redressing`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web-server config or response audit showing responses without `X-Frame-Options` or CSP `frame-ancestors` on authenticated pages.
- Referer headers on state-changing POSTs pointing to an unrelated external document that embedded the page.
- Sequences of two state changes within a few hundred milliseconds consistent with a double-click window-swap.
- Browser RUM telemetry reporting the page rendered inside a cross-origin frame (`window.top !== window.self`).
- A spike in a sensitive action (profile publish, permission grant) from sessions whose navigation lacks the normal in-app referrer chain.
- CSP violation reports (`report-uri` or `report-to`) citing `frame-ancestors` for the protected page.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
