# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-recon-and-content-discovery-archive-and-osint-recon`](SKILL.md) | Family: **Web and Application**

Fields, events, and queries that separate this technique from ordinary traffic. Operational detection engineering lives with the paired Blue skill.

## Primary Observable Signals

- Access logs showing requests for long-removed endpoints that only exist in historical snapshots.
- User-Agent strings matching waybackurls, gau, or httpx replaying archived URL lists.
- A burst of requests to paths that return 404 on the live site but map to old route patterns.
- Referrer headers or request patterns indicating URLs sourced from `web.archive.org` captures.
- Secret-scanning alerts (trufflehog, GitGuardian) firing on the organisation's public repositories.
- Authentication attempts using credentials that match patterns found in historical commits.
- Requests to decommissioned API versions (`/v1/`, `/legacy/`) absent from current routing tables.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) | Detection queries, triage, and hardening for this technique |
