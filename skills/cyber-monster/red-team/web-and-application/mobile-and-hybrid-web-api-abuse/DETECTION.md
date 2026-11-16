# Detection Signals and Blue-Team Handoff

> Sub-skill: [`mobile-and-hybrid-web-api-abuse`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- API gateway logs where a mobile client's User-Agent or token is used from a different IP or client fingerprint than the registered app.
- Requests to `/debug`, `/internal`, `/v0`, or `/v1` routes that the current app version does not call.
- Object-id parameters in API paths varying far beyond one user's normal range within a session (BOLA signal).
- Calls to admin or bulk-export functions by tokens whose role is a standard user (BFLA signal).
- The same static API key value seen across many distinct end-user sessions, consistent with a bundled key.
- 4xx-to-200 transitions on a route after the client-side validation parameters are dropped from the body.
- Spikes of direct API traffic with no preceding app-handshake or attestation event where one is expected.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
