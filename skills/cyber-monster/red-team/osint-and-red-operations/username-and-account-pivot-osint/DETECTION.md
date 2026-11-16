# Detection Signals and Blue-Team Handoff

> Sub-skill: [`username-and-account-pivot-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Enumeration of one handle across dozens of services from a single address in minutes.
- Requests to profile URLs that 404 for most services, the signature of an existence check.
- Keyserver lookups for addresses belonging to an organisation.
- Repository clones focused on author metadata.
- Automated avatar downloads from a set of candidate profiles.
- Rate-limit responses from multiple services to the same client fingerprint.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
