# Detection Signals and Blue-Team Handoff

> Sub-skill: [`osint-methodology-verification-and-bias`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Repeated fetches of the same article from many mirrors within one session, characteristic of a corroboration check.
- Automated retrieval of peering, routing, and CT data for one organisation in sequence.
- A single analyst account querying sources across unrelated jurisdictions in minutes.
- Archive queries for the same URL with different timestamps, indicating change verification.
- Export of a corroboration table to a personal device.
- Bulk WHOIS or RDAP lookups for a domain set from one address.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
