# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-recon-and-port-scanning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- NetFlow or Zeek `conn.log`: one source reaching more than 100 distinct destination ports on one host inside 60 seconds.
- Suricata `SURICATA STREAM` and `ET SCAN` signatures keyed on repeated half-open connections from a single source.
- Windows Filtering Platform audit event 5156 records allowed inbound connections with `Source Address` and `Destination Port`, useful when the scanner is internal.
- Host firewall log (Windows 5157 or `iptables -j LOG`) shows one source hitting sequential ports, which distinguishes scanning from a single failed connection.
- Zeek `scan` notice or `weird` events for SYN with unusual window size, the fingerprint of a raw-socket scanner rather than a browser.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
