# Detection Signals and Blue-Team Handoff

> Sub-skill: [`process-injection-techniques-classic-and-apc-injection`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 10 with a write mask on a target process, followed within seconds by event 8 for the same target.
- Sysmon event 8 where the `StartAddress` does not resolve to a module, which indicates unbacked executable memory.
- Windows Security 4656 for a process-object handle with `PROCESS_VM_WRITE`, where object auditing is enabled.
- Kernel telemetry for a protection change to `PAGE_EXECUTE_READWRITE` in a remote process.
- A source process with no prior cross-process access history, correlated with any event 8.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`memory-forensics-process-and-injection-analysis`](../../../blue-team/digital-forensics/memory-forensics-process-and-injection-analysis/SKILL.md) | Query authoring, triage logic, and hardening verification |
