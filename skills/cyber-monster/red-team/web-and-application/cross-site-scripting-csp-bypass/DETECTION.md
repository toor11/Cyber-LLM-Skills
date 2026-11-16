# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cross-site-scripting-csp-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Content-Security-Policy response headers whose script-src lists host origins without a nonce or strict-dynamic token.
- CSP response headers missing base-uri or form-action directives on pages that render login or payment forms.
- CSP violation reports (report-to or report-uri) that cluster on an allowlisted host serving a callback endpoint.
- Outbound form POSTs from authenticated pages to external origins, visible in referer and navigation logs.
- Requests to JSONP endpoints on allowlisted CDNs carrying a callback parameter that names a function.
- Trusted Types violation reports indicating require-trusted-types-for 'script' is set to report-only or absent.
- Injected base tags or script src values pointing off-origin in stored or reflected user content.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
