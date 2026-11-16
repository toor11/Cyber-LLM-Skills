# Detection Signals and Blue-Team Handoff

> Sub-skill: [`session-and-token-lifecycle-fixation-and-prediction`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Login requests carrying a session identifier in the URL query string or request body.
- Authenticated sessions whose identifier equals a value seen in the same client's pre-authentication traffic.
- Monotonically increasing or clock-correlated session identifier values in issuance logs.
- Set-Cookie on the login response repeating the identifier present on the pre-login response.
- Session identifiers shorter than the application's documented minimum length or from a restricted alphabet.
- Multiple accounts authenticating into the same identifier value over time.
- Bursts of landing-page hits from one client harvesting consecutive identifiers.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
