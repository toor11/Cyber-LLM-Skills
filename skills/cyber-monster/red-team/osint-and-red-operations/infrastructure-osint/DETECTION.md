# Detection Signals and Blue-Team Handoff

> Sub-skill: [`infrastructure-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Certificate transparency queries for a single domain in bulk from one address.
- Routing registry lookups for an ASN from a host outside network operations.
- RDAP queries enumerating registrant handles at machine speed.
- Sequential banner grabs across a prefix from one source address.
- DNS resolution of names that only appear in CT records, indicating a harvest followed by confirmation.
- Registry API key usage exceeding normal operational volume.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
