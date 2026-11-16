# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-protocol-attacks-capture-and-intercept`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Cisco `%SW_DAI-4-DHCP_SNOOPING_DENY` or `%IP-4-DUPADDR` syslog indicating a conflicting ARP claim.
- Zeek `arp` log showing one MAC answering for multiple IPs, or an IP claimed by two MACs in a short window.
- Windows event 4100 or `Get-NetNeighbor` drift on the endpoint, visible if endpoint telemetry captures neighbour changes.
- Gratuitous ARP bursts from a non-gateway port, which most switches can log or rate-limit.
- Flow asymmetry: a host whose traffic volume drops while its neighbour's rises, the pattern of a redirect in progress.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
