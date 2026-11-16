# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-protocol-attacks-ipv6-and-dhcp-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows event 4100 recording an unexpected IPv6 router address, logged by default and cheap to alert on.
- Zeek `dhcp` log with `msg_type: ADVERTISE` from a source that is not a configured DHCPv6 server.
- Switch DHCPv6 guard or RA guard drop counters incrementing on an access port.
- Endpoint resolver configuration change events, where the endpoint management platform records DNS server list changes.
- Flow records showing UDP 547 to 546 on a VLAN that has no DHCPv6 relay, which is anomalous by construction.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
