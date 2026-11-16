# Detection Signals and Blue-Team Handoff

> Sub-skill: [`open-redirect-chain-to-token-theft`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Authorization-server logs where a redirect_uri shares the registered prefix but carries an extra path segment or forwarding parameter.
- Token-endpoint exchanges whose preceding authorization request used a redirect_uri not in the exact registration list.
- Referer headers on resources loaded after /callback that contain a `code` or `access_token` query value.
- Authorization requests reusing the same state value across distinct sessions, or lacking state entirely.
- Callback responses issuing a further 302 to a host outside the application origin.
- Access tokens first seen in use from a network location different from the session that obtained them.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
