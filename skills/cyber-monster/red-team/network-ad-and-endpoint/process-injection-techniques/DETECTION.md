# Detection Signals and Blue-Team Handoff

> Sub-skill: [`process-injection-techniques`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 10 with `TargetImage` naming a sensitive process and `GrantedAccess` including a write mask.
- Sysmon event 8 where `SourceImage` differs from `TargetImage`, which is cross-process thread creation.
- Sysmon event 25 for image tampering with the modified region's base address and size.
- Windows Security 4656 for a handle to a process object with `PROCESS_VM_WRITE`, where object auditing is enabled.
- A source process whose cross-process access baseline is empty, correlated with a subsequent thread creation.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) | Query authoring, triage logic, and hardening verification |
