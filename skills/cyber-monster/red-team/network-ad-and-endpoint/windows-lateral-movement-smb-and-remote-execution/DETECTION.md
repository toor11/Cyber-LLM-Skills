# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-lateral-movement-smb-and-remote-execution`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 5140 and 5145 for `ADMIN$` or `C$` access with `Subject User Name` and `Source Address`.
- Service Control Manager event 7045 with a binary path outside `System32`, and Windows Security 4697 for the installation.
- Windows Security 4698 and TaskScheduler operational events for a task created without a corresponding GPO.
- Sysmon event 11 for a file written to `C:\Windows\` by a remote session.
- Windows Security 4624 logon type 3 with `Authentication Package: NTLM` from a workstation subnet to a server.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
