# Detection Signals and Blue-Team Handoff

> Sub-skill: [`osint-methodology`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Bulk queries against registry and CT endpoints from one source address, characteristic of scripted collection.
- Repeated retrieval of the same record at regular intervals, matching a scheduled provenance check.
- Access to breach or people-search APIs from a host outside the research subnet.
- SQLite or CSV files containing provider-named tables on endpoint storage.
- Egress from one process to several unrelated data providers within minutes.
- API key usage exceeding the licensed rate for an OSINT provider account.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
