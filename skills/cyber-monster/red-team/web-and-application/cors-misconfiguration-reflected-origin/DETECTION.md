# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cors-misconfiguration-reflected-origin`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access-Control-Allow-Origin response values that contain the trusted domain as a substring but are not in the configured allowlist.
- Reflected origins whose host portion appends an extra label to the trusted FQDN, indicating a defeated suffix check.
- Access-Control-Allow-Origin: null emitted in responses, correlated with Origin: null in the request.
- Repeated requests to one authenticated endpoint varying only the Origin header across many lookalike hostnames.
- Gateway configuration using startsWith, endsWith, or unanchored regex on the Origin header.
- Authenticated responses reflecting an Origin that resolves to an IP or host outside the organisation's ASN.
- A surge of OPTIONS and GET pairs from homoglyph or punycode Origin values against account APIs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
