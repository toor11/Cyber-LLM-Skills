# Detection Signals and Blue-Team Handoff

> Sub-skill: [`osint-identity-and-email-correlation`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Keyserver searches for internal addresses from an external host.
- Sequential enumeration of handles across many platforms at machine speed.
- Git repository cloning focused on author metadata rather than code changes.
- Avatar hashing utilities run over a downloaded profile image set.
- Repeated queries for one address across breach-check APIs.
- Access to people-search services from a single client in a burst.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
