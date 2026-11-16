# Detection Signals and Blue-Team Handoff

> Sub-skill: [`authentication-bypass-forced-browsing`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Web access logs where /Admin, /admin/. or /admin%2f returns 200 while /admin returns 302 or 401.
- Requests to protected paths carrying dot segments, double slashes, or matrix parameters.
- Reverse-proxy logs where the normalised path differs from the path the origin logged for the same request id.
- 200 responses to .json or alternate-extension variants of routes that normally require a session.
- A client retrieving admin content with no preceding authentication event in the session log.
- Spikes of 404-to-200 transitions on path-fuzzing patterns from a single source.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
