# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authentication-bypass-header-and-proxy-trust`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Requests carrying X-Original-URL or X-Rewrite-URL headers that differ from the request-line path.
- Inbound X-Forwarded-For values of 127.0.0.1 or RFC1918 addresses arriving from external source IPs.
- Access to internal-only routes correlated with a client-supplied X-Internal or role header.
- Reverse-proxy logs showing a hop-by-hop or trust header that was not stripped at the edge.
- X-Forwarded-Host values that do not match the site's configured host set.
- A 200 on an internal route whose authorisation log records the client IP as loopback.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
