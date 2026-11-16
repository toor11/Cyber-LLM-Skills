# Detection Signals and Blue-Team Handoff

> Sub-skill: [`jwt-oauth-and-oidc-audit-cli-development`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Repeated fetches of `/.well-known/openid-configuration` and `jwks_uri` from one client in a short window.
- Token decode attempts producing signature errors at a steady rate, characteristic of a probe loop against the verifier.
- Requests to the token endpoint with `grant_type=authorization_code` and a mismatched `redirect_uri`.
- Authorization requests omitting `code_challenge` from a public client, visible in the IdP's own audit log.
- `/introspect` or `/userinfo` calls from a client that never completed a login in the same session.
- JWKS fetch spikes correlated with a single source address rather than distributed validator traffic.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`ci-cd-security-gate-and-sarif-tooling`](../../../blue-team/security-automation-and-tool-development/ci-cd-security-gate-and-sarif-tooling/SKILL.md) | Query authoring, triage, and hardening |
