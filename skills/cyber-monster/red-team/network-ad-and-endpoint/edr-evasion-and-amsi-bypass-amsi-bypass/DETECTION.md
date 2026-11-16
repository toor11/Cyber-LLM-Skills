# Detection Signals and Blue-Team Handoff

> Sub-skill: [`edr-evasion-and-amsi-bypass-amsi-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 7 for `amsi.dll` loaded from a path other than `System32`, which is the redirection signature.
- Defender event 1116 or 1117 with an AMSI-sourced threat name, which records a scan verdict.
- PowerShell event 4104 followed by no 1116 for the same window, the differential a detection rule can encode.
- Windows Security 4657 for a change to the AMSI provider registry key.
- Sysmon event 10 for a process opening its own memory with write access, the in-memory patch pattern.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) | Query authoring, triage logic, and hardening verification |
