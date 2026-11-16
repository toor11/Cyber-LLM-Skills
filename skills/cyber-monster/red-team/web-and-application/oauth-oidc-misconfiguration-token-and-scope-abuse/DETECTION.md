# Detection Signals and Blue-Team Handoff

> Sub-skill: [`oauth-oidc-misconfiguration-token-and-scope-abuse`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Resource-server logs accepting tokens whose aud claim names a different client or API.
- Access-token validations that log signature and expiry checks but no aud or iss comparison.
- Protected calls succeeding with a scope broader than the client's configured entitlement.
- Refresh-token exchanges where the same refresh_token value is redeemed more than once (no rotation).
- A refresh token used from a client id different from the one it was issued to.
- Tokens honoured after a corresponding revocation event in the authorization server.
- Introspection responses whose scope or audience disagree with what a downstream resource enforced.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Detection queries, triage, and hardening for this technique |
