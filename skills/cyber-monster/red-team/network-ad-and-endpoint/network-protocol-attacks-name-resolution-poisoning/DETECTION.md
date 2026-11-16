# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-protocol-attacks-name-resolution-poisoning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Zeek `dns` or `nbns` log with a response from a host that is not in the resolver inventory, especially from a workstation address.
- Windows Security 4624 logon type 3 on the responder host, or 5145 share access, which records the victim's authentication to the wrong server.
- Sysmon event 3 on the victim showing an SMB or HTTP connection to an internal address outside the server inventory.
- Sigma-style correlation: LLMNR query from host A followed within seconds by SMB to host A from the same victim.
- DNS client cache events or Sysmon event 22 showing resolution of a name that the DNS server never answered.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
