# Detection Signals and Blue-Team Handoff

> Sub-skill: [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 1 for a process that spawns `systeminfo`, `wmic` or a WMI query immediately after launch, the probing pattern.
- Sysmon event 11 for a file written after a long sleep, where the delay is the timing check.
- Sysmon event 22 for a DNS lookup of an analysis-service domain, the environment check by name.
- WMI-Activity events for `Win32_ComputerSystem` and `Win32_BIOS` queries from a newly created process.
- Registry reads of `HKLM\HARDWARE\DESCRIPTION\System\BIOS` in sequence with disk enumeration, the fingerprinting sequence.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) | Query authoring, triage logic, and hardening verification |
