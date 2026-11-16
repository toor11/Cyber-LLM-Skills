# Detection Signals and Blue-Team Handoff

> Sub-skill: [`websocket-security`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- HTTP Upgrade requests in the proxy log whose Origin header host is not in the application's allowlist.
- 101 Switching Protocols responses to handshakes where Origin and Host differ.
- WebSocket handshakes carrying a session cookie but a Referer pointing to an unrelated external site.
- A single session opening sockets to privileged channels immediately after navigating from an external referrer.
- Server logs showing a CheckOrigin or origin-validation function returning allow for every Origin value.
- Frame volume or size on one connection far exceeding the per-session norm, indicating a missing rate or size cap.
- Subscription channels delivering another user's record ids to a connection that authenticated at a lower privilege.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
