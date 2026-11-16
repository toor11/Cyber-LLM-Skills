# Detection Signals and Blue-Team Handoff

> Sub-skill: [`windows-lateral-movement`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 logon type 3 or 10 with `Source Network Address` outside the management subnet.
- Service Control Manager event 7045 and Windows Security 4697 for remote service installation.
- Windows Security 4688 with `WmiPrvSE.exe` or `wsmprovhost.exe` as parent, indicating remote process creation.
- Windows Security 5140 and 5145 for admin share access from a workstation address.
- Windows Security 4672 for special privileges assigned to a network logon, which accompanies administrative lateral movement.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
