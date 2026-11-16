# Detection Signals and Blue-Team Handoff

> Sub-skill: [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 10 where `SourceImage` equals `TargetImage` with a write mask, indicating self-modification.
- Sysmon event 8 for `CreateRemoteThread` into a security product process.
- EDR alert on a process reading `ntdll.dll` from disk shortly after start, the unhooking pattern.
- Kernel callback telemetry for a process image that does not match its on-disk hash, where the product supports it.
- Windows Security 4657 for changes to a security product's protection registry values.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) | Query authoring, triage logic, and hardening verification |
