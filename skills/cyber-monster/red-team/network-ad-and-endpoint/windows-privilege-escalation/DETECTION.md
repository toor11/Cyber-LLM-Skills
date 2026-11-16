# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-privilege-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4688 for a service binary being replaced, or for `sc.exe config` with a new `binPath`.
- Windows Security 4657 for a change to a service key value such as `ImagePath`.
- Sysmon event 11 for a file written into a service directory by a non-installer process.
- Windows Security 4672 for special privileges assigned to a logon where the account normally has none.
- Service Control Manager event 7045 for a new service installed, which records the binary path and account.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad/SKILL.md) | Query authoring, triage logic, and hardening verification |
