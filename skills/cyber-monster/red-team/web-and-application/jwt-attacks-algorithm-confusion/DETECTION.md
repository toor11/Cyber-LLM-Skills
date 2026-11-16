# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jwt-attacks-algorithm-confusion`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Verifier logs showing an accepted token whose header alg is HS256 on a service that issues RS256.
- Library debug logs where the same key object is passed to both the HMAC and the RSA verify paths.
- 200 responses to tokens whose signature was computed over the published public-key material.
- SIEM rule firing on alg header values of none or HS256 for audiences that only mint ES256 or RS256.
- A spike in JWT verification using symmetric algorithms recorded by the auth-middleware metrics.
- Access to the JWKS endpoint immediately followed by authenticated requests from the same client using HS256.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
