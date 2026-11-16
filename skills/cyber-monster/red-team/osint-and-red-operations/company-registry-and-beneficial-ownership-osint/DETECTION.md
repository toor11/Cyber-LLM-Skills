# Detection Signals and Blue-Team Handoff

> Sub-skill: [`company-registry-and-beneficial-ownership-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Registry and LEI API queries for a company name set from one address.
- Sequential entity lookups enumerating registration numbers.
- Securities filing index downloads for a single issuer in bulk.
- Access to corporate registry APIs from a host outside the research subnet.
- Rate-limit responses from a registry provider to one API key.
- Exports of ownership tables to shared or removable storage.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
