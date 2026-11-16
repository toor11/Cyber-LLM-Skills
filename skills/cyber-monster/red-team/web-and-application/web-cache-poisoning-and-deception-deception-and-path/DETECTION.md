# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-cache-poisoning-and-deception-deception-and-path`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Edge logs showing requests to authenticated paths with appended static extensions (`.css`, `.js`) returning `X-Cache: HIT`.
- Responses to `/account` or `/profile` style paths carrying `Cache-Control: public` or no cache directive at the origin.
- Unauthenticated requests, carrying no session cookie, receiving bodies that contain per-user fields.
- A single path requested first with a victim session then without one for the same suffixed URL.
- Path parameters or extra segments on dynamic routes recorded at the edge but absent in origin routing.
- Cache entries whose stored content type is HTML while the requested extension was `.css` or `.js`.
- Lure URLs with trailing static suffixes appearing in referrer logs for authenticated users.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
