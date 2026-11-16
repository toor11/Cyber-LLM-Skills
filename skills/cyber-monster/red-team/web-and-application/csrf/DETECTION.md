# Detection Signals and Blue-Team Handoff

> Sub-skill: [`csrf`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web access logs where a state-changing POST carries a `Referer` from a host outside the application's own origin list.
- Requests to account-mutation routes where the `Origin` header is present and does not match the target host.
- State-changing requests arriving without the framework's CSRF cookie or header on a route that normally includes both.
- A single session performing an account change within seconds of a navigation to an unrelated external referrer.
- Session cookie `Set-Cookie` lines that omit `SameSite` or set it to `None` without `Secure`.
- GET requests to routes that mutate state, which is the precondition for lax-cookie forgery.
- Bursts of identical form-encoded POST bodies from many distinct sessions to the same mutation route, characteristic of a distributed forged campaign.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`authentication-and-session-design-review`](../../../blue-team/application-security/authentication-and-session-design-review/SKILL.md) | Detection queries, triage, and hardening for this technique |
