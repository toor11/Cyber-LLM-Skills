# Detection Signals and Blue-Team Handoff

> Sub-skill: [`web-archival-and-deleted-content-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Archive CDX queries for a single URL at high frequency, characteristic of change monitoring.
- Crawl index downloads enumerating a domain's paths.
- Repeated retrieval of the same capture playback URL, indicating citation verification.
- Access to archive APIs from a host outside the research subnet.
- Bulk capture downloads stored to disk in a short window.
- Queries for URLs that no longer resolve, the signature of deleted-content recovery.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
