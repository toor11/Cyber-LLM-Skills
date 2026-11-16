# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-recon-and-content-discovery-directory-and-file`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access-log bursts where one client requests hundreds of distinct paths per minute with a high ratio of 404 status codes.
- Requests for `/.git/`, `/.svn/`, or `/.env` in the URI field of the web access log from an unauthenticated source.
- A spike in 200 responses for paths ending in `.bak`, `.old`, `.zip`, or `.sql` that are never referenced by any page.
- User-Agent strings matching ffuf, gobuster, feroxbuster, or dirsearch in the request log.
- Repeated requests that differ only in the Host header against the same URI, indicating virtual-host enumeration.
- WAF rule hits for content-discovery signatures followed by a 200 from the origin on the same path.
- Directory-listing responses (autoindex) served for folders that have no linked index page.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
