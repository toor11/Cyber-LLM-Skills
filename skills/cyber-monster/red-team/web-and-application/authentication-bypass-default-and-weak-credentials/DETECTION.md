# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authentication-bypass-default-and-weak-credentials`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Login success events for the username admin from an external IP shortly after deployment.
- Authentication logs where consecutive failures for one account never trigger a lockout or 429.
- Account-service records showing an admin login while the must_rotate flag is still set.
- Setup or install wizard routes returning 200 after the application is already provisioned.
- A burst of single-attempt logins across many accounts from one source using a common password.
- Submitted username and password pairs matching known vendor-default combinations.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
