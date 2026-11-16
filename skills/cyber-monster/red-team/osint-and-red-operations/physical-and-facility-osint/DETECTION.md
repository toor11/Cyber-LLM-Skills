# Detection Signals and Blue-Team Handoff

> Sub-skill: [`physical-and-facility-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Registry searches by address rather than by name, a signature of occupancy mapping.
- Planning portal queries for a postcode in bulk.
- Imagery tile downloads around a single coordinate.
- Access to property or permit APIs from a host outside the research subnet.
- Rate-limit responses from a registry provider for one key.
- Exports of a site table containing occupant names to shared storage.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
