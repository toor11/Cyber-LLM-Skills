# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-lateral-movement-rdp-and-session-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 logon type 10 with `Source Network Address` outside the jump-host range.
- TerminalServices-LocalSessionManager event 1149 for an authenticated session, which records the source address and user.
- TerminalServices-RemoteConnectionManager event 1149 for a failed or successful connection attempt, including pre-auth failures.
- `Microsoft-Windows-TerminalServices-RDPClient/Operational` event 1024 on the source host, recording the target it connected to.
- Windows Security 4688 for `tscon` or `mstsc /shadow`, where command-line auditing is enabled.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
