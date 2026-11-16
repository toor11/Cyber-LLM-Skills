# Detection Signals and Blue-Team Handoff

> Sub-skill: [`session-and-token-lifecycle`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Authentication logs where a session identifier is used after its /logout event timestamp for the same account.
- Set-Cookie headers on the login response missing Secure, HttpOnly, or SameSite attributes.
- The same session identifier appearing from two distinct source IPs or user agents concurrently.
- Session store records never deleted on password-change or account-disable events.
- Requests authenticated with an identifier issued before the last credential-rotation event.
- Cookie Domain attributes scoped to a registrable parent domain shared with user-content subdomains.
- Stateless tokens presented after a logout with no corresponding entry in a revocation list.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
