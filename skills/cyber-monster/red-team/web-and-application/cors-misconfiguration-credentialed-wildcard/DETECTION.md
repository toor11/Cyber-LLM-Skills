# Detection Signals and Blue-Team Handoff

> Sub-skill: [`cors-misconfiguration-credentialed-wildcard`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Responses pairing Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true at the gateway or application tier.
- Access-Control-Allow-Origin values that are subdomains of a trusted parent but absent from the configured allowlist.
- Credentialed API responses whose echoed Origin resolves to a recently registered host under a first-party parent domain.
- CORS policy configuration using a suffix or endsWith match on the apex domain rather than an enumerated origin set.
- DNS monitoring flagging dangling CNAMEs for subdomains that appear in CORS allow-origin responses.
- A rise in credentialed cross-origin fetches from distinct sibling subdomains to the same authenticated endpoint.
- Vary: Origin absent on credentialed responses served through a shared CDN cache.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
