# Detection Signals and Blue-Team Handoff

> Sub-skill: [`oauth-oidc-misconfiguration`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Authorization-server logs where an accepted redirect_uri differs from the client's registered value by path or subdomain.
- Token-endpoint events accepting a code_verifier with no recorded code_challenge for that authorization request.
- Callback requests to the relying party lacking a state parameter or reusing a prior state value.
- Access tokens presented to a resource server whose aud claim names a different client.
- id_token validations missing a nonce comparison against the session in client logs.
- Consent or grant records where the granted scope exceeds the client's configured maximum.
- Account-linking events associating an external identity to a local account without a prior email-verification event.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Detection queries, triage, and hardening for this technique |
