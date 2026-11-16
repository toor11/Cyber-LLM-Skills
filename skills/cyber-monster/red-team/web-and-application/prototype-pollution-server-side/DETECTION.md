# Detection Signals and Blue-Team Handoff

> Sub-skill: [`prototype-pollution-server-side`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Request bodies containing __proto__ keys posted to JSON API endpoints.
- qs-style [__proto__] bracket keys appearing in query strings.
- APM call sites for lodash merge or defaultsDeep correlated with request bodies.
- A config or auth default changing mid-session with no deployment event.
- Worker process restarts correlated in time with pollution requests.
- Bursts of 'Cannot convert undefined' or 'is not a function' errors after a specific request.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
