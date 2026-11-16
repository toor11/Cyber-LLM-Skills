# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-recon-and-content-discovery`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs with a high rate of 404 responses to sequential, wordlist-like paths from one source IP.
- Requests for backup and source-map suffixes (`.bak`, `.old`, `.js.map`, `~`) recorded in the web server log.
- `Host` header values that do not match configured virtual hosts arriving from one client.
- User-Agent strings matching ffuf, feroxbuster, gobuster, or dirsearch in access logs.
- A burst of requests to `robots.txt`, `sitemap.xml`, and the paths they list in quick succession.
- Requests to administrative paths (`/admin`, `/actuator`, `/.git/`) that are absent from site navigation.
- Recursive directory patterns where each discovered directory triggers a new wave of child requests.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
