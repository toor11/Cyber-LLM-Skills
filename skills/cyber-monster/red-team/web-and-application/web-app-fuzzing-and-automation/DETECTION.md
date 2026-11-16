# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-app-fuzzing-and-automation`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs showing one client requesting hundreds of distinct values on a single path or parameter within a short window.
- A high ratio of 404 or error responses from one source IP across sequential wordlist-like paths.
- User-Agent strings matching ffuf, nuclei, gobuster, or feroxbuster in the web server log.
- 429 or Retry-After responses issued to a single source correlated with sequential parameter values.
- Response-length variance on one endpoint queried with many inputs, visible in the access-log byte field.
- Requests carrying a random cache-buster parameter appended to every URL, a hallmark of calibrated fuzzing.
- A burst of requests sharing one session cookie but cycling a path variable, recorded by the application router.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
