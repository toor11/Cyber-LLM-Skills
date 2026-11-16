# Detection Signals and Blue-Team Handoff

> Sub-skill: [`oauth-oidc-misconfiguration-flow-and-state-flaws`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Relying-party callback logs lacking a state parameter or showing a repeated state value across users.
- Token-endpoint events with a code_verifier where the matching authorization request logged no code_challenge.
- code_challenge_method=plain appearing in authorization requests where policy requires S256.
- id_token validation logs missing a nonce comparison, or the same nonce seen in two sessions.
- Authorization codes issued by one iss redeemed at a client configured for a different iss (mix-up).
- response_type=token authorization requests indicating implicit-flow use.
- A session established immediately after a callback whose referrer is an external attacker-controlled page (login CSRF).

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Detection queries, triage, and hardening for this technique |
