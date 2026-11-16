# Detection Signals and Blue-Team Handoff

> Sub-skill: [`osint-operational-security`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Queries to registry or OSINT providers originating from a corporate egress address rather than the assessment egress.
- Newly created accounts on external services from a corporate IP, indicating persona creation from the office.
- Collection traffic to the target's own services from an address the client recognises.
- Persona-linked logins after the engagement end date.
- OSINT provider API keys used from more than one egress within a session.
- Bulk downloads of collected material to a personal device.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
