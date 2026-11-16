# Detection Signals and Blue-Team Handoff

> Sub-skill: [`host-persistence-registry-and-service-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 12 and 13 for registry value creation and modification under the autostart keys, with `TargetObject` and `Details`.
- Windows Security 4697 and Service Control Manager 7045 for service installation with an unusual path.
- Sysmon event 7 for a DLL loaded from a user-writable directory into a privileged process, the COM hijack signature.
- File integrity monitoring on `System32` and `Program Files` for new binaries, plus signature validation.
- Registry auditing (SACL) on the `Run` keys, which records the writing principal and is the direct control.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
