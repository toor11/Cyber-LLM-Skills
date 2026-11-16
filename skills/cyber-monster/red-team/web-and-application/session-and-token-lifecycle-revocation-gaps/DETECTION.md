# Detection Signals and Blue-Team Handoff

> Sub-skill: [`session-and-token-lifecycle-revocation-gaps`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- API requests authenticated by a bearer token whose unique id is absent from the issuance store yet still accepted.
- Authenticated requests using a session whose logout event is already recorded for that identifier.
- Successful authorization at a privilege level a recorded role-downgrade event should have removed.
- Activity from an account after its disable or deprovision event timestamp.
- Refresh-token grants where the presented token was already rotated to a successor.
- Absence of denylist writes in logout handlers for stateless-token deployments.
- The same token presented from multiple IPs continuing to work after a password-reset event.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
