# Detection Signals and Blue-Team Handoff

> Sub-skill: [`corporate-and-person-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Directory or team-page enumeration at a steady request rate from one address.
- Mail gateway probes for many generated addresses in a short window, the signature of convention testing.
- Registry and RDAP queries for a domain set from a single client.
- Access to people-search APIs from a host outside the research subnet.
- Scraping user-agents against pages that normally receive browser traffic.
- Bulk export of a people table to removable media.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
