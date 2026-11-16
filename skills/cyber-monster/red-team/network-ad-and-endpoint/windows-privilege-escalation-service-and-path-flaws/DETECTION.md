# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-privilege-escalation-service-and-path-flaws`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Service Control Manager event 7040 for a service start-type change, which records a reconfiguration.
- Windows Security 4657 for a change to `ImagePath` under a service key.
- Sysmon event 11 for a file created in a directory that contains a service binary.
- Service Control Manager event 7045 for a new service, including its binary path and account.
- Windows Security 4688 for `sc.exe` with `config` or `create` in the command line.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) | Query authoring, triage logic, and hardening verification |
