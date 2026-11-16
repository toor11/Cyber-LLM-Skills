# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-protocol-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Duplicate ARP replies for the same IP from two MACs, visible in Zeek `arp` log or switch dynamic ARP inspection drops.
- Cisco `%SW_DAI-4-DHCP_SNOOPING_DENY` or `%IP-4-DUPADDR` syslog, which records the conflict at the device that owns the gateway.
- Zeek `nbns` or `dns` log with responses arriving from a host that is not a configured resolver.
- Windows event 4100 (ISATAP router configuration) recording an unexpected IPv6 address as the router, the marker of a rogue RA or DHCPv6 answer.
- Switch MAC-move notifications for the gateway MAC appearing on an access port.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
