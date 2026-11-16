# Detection Signals and Blue-Team Handoff

> Sub-skill: [`edr-evasion-and-amsi-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4657 for a change to Defender policy values such as exclusions or real-time protection.
- Defender event 5010 or 5012 for tamper protection blocking a configuration change.
- Sysmon event 6 for a driver load that matches a known vulnerable driver, the EDR-kill precursor.
- Sysmon event 8 for `CreateRemoteThread` into a security product process.
- Gap detection in the SIEM: a host that normally reports heartbeats and stops, correlated with a sensor service stop event.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`endpoint-detection-and-edr-operations`](../../../blue-team/detection-and-monitoring/endpoint-detection-and-edr-operations/SKILL.md) | Query authoring, triage logic, and hardening verification |
