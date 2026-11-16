# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-lateral-movement-winrm-and-wmi`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4688 with `Creator Process Name` naming `wsmprovhost.exe` or `WmiPrvSE.exe`.
- PowerShell event 4103 and 4104 for script blocks executed in a remote session, with `Host Application` naming the WinRM host.
- Windows Security 4624 logon type 3 with `Authentication Package: NTLM` on port 5985 traffic, visible in firewall logs alongside the logon.
- WinRM operational log event 91 or 142 for a shell created by a principal outside the administration group.
- WMI-Activity operational log event 5857 or 5861 for provider operations initiated remotely.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
