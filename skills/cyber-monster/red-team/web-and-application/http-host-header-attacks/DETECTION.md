# Detection Signals and Blue-Team Handoff

> Sub-skill: [`http-host-header-attacks`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web access logs where `X-Forwarded-Host` or `Host` differs from the configured domain on password-reset or verification routes.
- Outbound email or notification events whose embedded links use a host not in the configured allowlist.
- Cache entries keyed without the host where response bodies contain varying host values.
- Reverse-proxy logs showing `Forwarded` or `X-Forwarded-Host` values that do not match the server name.
- Redirect `Location` headers echoing an inbound host that differs from the canonical domain.
- Server-side fetch logs whose target host originates from a request header on a host-routed endpoint.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
