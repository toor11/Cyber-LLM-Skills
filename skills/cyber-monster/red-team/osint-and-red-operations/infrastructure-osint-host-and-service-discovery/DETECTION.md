# Detection Signals and Blue-Team Handoff

> Sub-skill: [`infrastructure-osint-host-and-service-discovery`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Dataset API key usage from an address outside the research subnet, or volume above the licensed tier.
- Sequential queries for adjacent prefixes, characteristic of a range sweep.
- Certificate and fingerprint lookups for a brand name at machine speed.
- Current confirmation requests that follow dataset queries within seconds.
- Exported service inventories written to shared storage.
- Queries using a brand string rather than a network filter, indicating unfiltered discovery.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
