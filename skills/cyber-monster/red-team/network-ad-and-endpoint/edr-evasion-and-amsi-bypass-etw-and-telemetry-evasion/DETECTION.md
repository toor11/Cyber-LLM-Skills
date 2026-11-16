# Detection Signals and Blue-Team Handoff

> Sub-skill: [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 1100 for the event logging service stopping, and 1102 for a log being cleared.
- System event 7034 or 7035 for a service crash or state change, where the service is the logging service.
- Defender event 5007 for a configuration change to the security product, which is a tampering signal.
- Cross-host anomaly: a host whose Sysmon or Security record count falls below the peer group median by a large factor.
- Sysmon event 8 for `CreateRemoteThread` into `Sysmon.exe`, `MsMpEng.exe` or the EDR agent process.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) | Query authoring, triage logic, and hardening verification |
