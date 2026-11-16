# Detection Signals and Blue-Team Handoff

> Sub-skill: [`service-enumeration-smb-and-netbios`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 logon type 3 with `Account Name: ANONYMOUS LOGON` on a member server, the direct record of a null session.
- Windows Security 5140 and 5145 record share access with the `Share Name` and `Relative Target Name`, which separates enumeration from file access.
- Sysmon event 3 to TCP 445 from a host that issues no session setup afterwards, the signature of negotiation-only probing.
- Zeek `smb_mapping` log listing tree connects from an unauthenticated session.
- NetBIOS name query bursts on UDP 137 from one source against a range, visible in Zeek `nbns` or firewall logs.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
