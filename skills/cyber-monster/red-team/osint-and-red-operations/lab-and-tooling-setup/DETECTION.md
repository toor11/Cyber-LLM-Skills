# Detection Signals and Blue-Team Handoff

> Sub-skill: [`lab-and-tooling-setup`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Traffic from a lab subnet reaching production ranges, which the isolation test should have prevented.
- New virtual network interfaces configured in bridged mode on an analysis host.
- Tool installation events on a host that is not in the lab inventory.
- Outbound package downloads from a lab environment that is supposed to be offline.
- Shared folder or clipboard activity between a lab guest and a corporate laptop.
- Snapshot deletions that remove the pre-scenario restore point.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
