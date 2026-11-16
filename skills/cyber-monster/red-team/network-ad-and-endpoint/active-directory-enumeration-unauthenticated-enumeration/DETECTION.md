# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-enumeration-unauthenticated-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 with `Account Name: ANONYMOUS LOGON` and `Logon Type 3` on a domain controller.
- Windows Security 4625 with `Status 0xC000006D` repeated from one address, the signature of anonymous probing against a patched DC.
- Directory diagnostic 1644 for a search with base `DC=` and scope subtree issued without a bind.
- DNS server log or Zeek `dns` log showing SRV queries for `_msdcs` from a host outside the server subnet.
- NetFlow to TCP 389 or 445 from a workstation segment to domain controllers, where normal traffic is workstation-to-workstation.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
