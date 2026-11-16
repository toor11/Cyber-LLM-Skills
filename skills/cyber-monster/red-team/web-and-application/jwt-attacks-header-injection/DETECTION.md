# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jwt-attacks-header-injection`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- JWT headers containing kid values with path-traversal sequences, a NUL, or SQL metacharacters.
- Outbound fetches to a jku or x5u URL whose host is not the trusted issuer, logged by the egress proxy.
- Tokens carrying a self-contained jwk header (an embedded public key) accepted by the verifier.
- Auth-middleware logs resolving a key from a request-supplied kid against a filesystem or SQL lookup.
- JWKS fetches initiated by the resource server to hosts outside the issuer allowlist.
- 200 responses to tokens whose kid points at a predictable or empty key file.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
