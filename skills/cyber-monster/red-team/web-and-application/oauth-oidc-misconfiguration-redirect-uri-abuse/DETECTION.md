# Detection Signals and Blue-Team Handoff

> Sub-skill: [`oauth-oidc-misconfiguration-redirect-uri-abuse`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Authorization-server logs where the accepted redirect_uri differs from the client's registered value by path, case, or trailing slash.
- Authorization requests with redirect_uri containing %2e%2e, @, backslash, or double-encoding.
- Codes issued to subdomains or hosts not in the client's registered redirect set.
- 302 responses from registered hosts whose Location forwards an authorization code or token fragment to an external domain.
- A surge of authorize requests varying only the redirect_uri from one source (matching-rule probing).
- Implicit-flow authorize requests (response_type=token) paired with tampered redirect hosts.
- Client registration changes that introduce wildcard or broad redirect patterns.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Detection queries, triage, and hardening for this technique |
