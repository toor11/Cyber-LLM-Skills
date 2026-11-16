# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-internals-and-api-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 1 with an unusual parent-child relationship where the child requests a broader token, such as `svchost.exe` spawning a shell.
- Windows Security 4672 for special privileges assigned to a new logon, with the `Privileges` field naming the set.
- Windows Security 4657 for a registry value change under a service key, which records a reconfiguration attempt.
- Sysmon event 10 for a process opening another with `PROCESS_ALL_ACCESS`, the handle request pattern behind token theft.
- Windows Security 4688 with `Token Elevation Type` recorded, where command-line auditing includes it.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
