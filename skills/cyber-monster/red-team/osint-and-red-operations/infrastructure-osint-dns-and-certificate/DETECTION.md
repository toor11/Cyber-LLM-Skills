# Detection Signals and Blue-Team Handoff

> Sub-skill: [`infrastructure-osint-dns-and-certificate`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Authoritative DNS queries for many names in one zone from a single resolver address.
- Certificate transparency queries for a domain at a rate no browser would produce.
- DNS queries for randomly generated labels, the signature of wildcard testing.
- Repeated NS and MX lookups for a domain set from one host.
- Passive DNS provider API usage exceeding the licensed quota for one key.
- Resolution attempts for names harvested from CT records within seconds of the harvest.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
