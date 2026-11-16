# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jwt-attacks`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Auth-gateway logs recording JWTs whose header alg equals none, None, or an unexpected family for the endpoint.
- Repeated 401 or 403 then 200 from the same client on a bearer-protected route, indicating token-forgery iteration.
- Tokens presented with a valid structure but a signature segment of zero length.
- SIEM comparison of the kid and alg header distribution per client against the issuer's normal values.
- Access logs showing the same sub claim arriving from many source IPs within a short window.
- Identity-provider logs lacking a corresponding issuance event for a sub or jti the resource server accepted.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
