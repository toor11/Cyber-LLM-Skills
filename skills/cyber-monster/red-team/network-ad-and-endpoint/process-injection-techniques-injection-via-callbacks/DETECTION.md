# Detection Signals and Blue-Team Handoff

> Sub-skill: [`process-injection-techniques-injection-via-callbacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- ETW provider events for thread-pool work-item registration with a start address outside any module.
- EDR telemetry showing a window-procedure pointer change on a GUI process.
- Sysmon event 7 for a DLL loaded by a process that then executes without a thread-creation event.
- Memory-image triage showing unbacked executable regions in a process with no network or file activity.
- Correlation gap: an outbound connection from a process with no creation event in the same window.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) | Query authoring, triage logic, and hardening verification |
