# Detection Signals and Blue-Team Handoff

> Sub-skill: [`service-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Zeek `smb_cmd` or `dce_rpc` log showing `Negotiate` or `Bind` from a host that never authenticates afterwards.
- Windows Security 4625 or 4776 burst with `Status 0xC000006D` from one source, the signature of anonymous probing against a hardened host.
- LDAP search with base `''` and scope `base` logged by the directory's 1644 diagnostic or a proxy access log.
- SNMP `sysDescr` read from outside the management subnet, visible in device ACL counters or flow records on UDP 161.
- Sysmon event 3 from the scanning host showing sequential `DestinationPort` across one destination, which ties enumeration to a source process.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
