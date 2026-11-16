# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-service-and-scheduled-task-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Service Control Manager event 7045 with `Image Path` outside `System32` or `Program Files`.
- Windows Security 4697 for a service installation, which records the account and the service name.
- Windows Security 4698 with a task author that is not a machine or a sanctioned administrator.
- TaskScheduler operational event 106 for a task registered, with the task path and the user context.
- Sysmon event 1 for a process whose parent is `services.exe` but whose image is in a user-writable directory.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
