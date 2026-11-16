# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authentication-bypass`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs where a protected route returns 200 with no session cookie or Authorization header present.
- Authentication service logs showing a session issued without a preceding successful credential or MFA event.
- JWT validation errors (alg mismatch or signature failure) logged immediately before a 200 on the same route.
- A single source cycling through many usernames against /login at stable low latency.
- Session-store entries created for a user id that has no corresponding login record.
- Requests to post-login step endpoints such as step2 or verify without the preceding stage cookie.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
