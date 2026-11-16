# Detection Signals and Blue-Team Handoff

> Sub-skill: [`adversary-emulation-planning`](SKILL.md) | Family: **OSINT and Red Operations**

Telemetry this technique produces while it runs, expressed as the field or event a detection would key on. Full engineering lives with the Blue counterpart.

## Primary Observable Signals

- Process creation sequences matching known discovery command sets from a single host in a brief window.
- Credential-access handle opens against sensitive processes from a non-standard binary.
- Lateral movement authentication events from a host that does not normally initiate them.
- A cluster of ATT&CK-aligned behaviours from one subnet during a declared window, which the deconfliction marker should explain.
- New service or scheduled task creation with names that do not match the environment's conventions.
- EDR alerts firing on a host that has no previous alert history, coinciding with a scheduled exercise.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) | Query authoring, triage, and hardening |
