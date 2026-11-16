# Detection Signals and Blue-Team Handoff

> Sub-skill: [`host-persistence-scheduled-and-wmi-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4698 with `Task Name` and `Subject User Name`, and 4699 for a task deleted, which records both sides.
- TaskScheduler operational event 106 for a task registered and 141 for a task deleted, with the task path.
- WMI-Activity operational event 5861 for a permanent subscription registered, which is the direct subscription record.
- Sysmon event 19, 20 and 21 for WMI filter, consumer and binding registration, where Sysmon is deployed.
- Windows Security 4688 for `schtasks /create` or a PowerShell `Register-ScheduledTask` invocation from an unusual parent.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
