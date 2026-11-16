# Detection Signals and Blue-Team Handoff

> Sub-skill: [`process-injection-techniques-hollowing-and-stomping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 25 with the `BaseAddress` and `ImageSize` of the modified region.
- Sysmon event 1 for a process created with `CREATE_SUSPENDED` semantics, visible as a long gap before thread activity.
- EDR telemetry for a thread whose start address is not within any loaded module.
- Memory-scanning alerts for `PAGE_EXECUTE_READWRITE` regions without a file backing.
- Code integrity or module-load events showing a module whose hash differs from the catalog.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) | Query authoring, triage logic, and hardening verification |
