# Detection Signals and Blue-Team Handoff

> Sub-skill: [`pivoting-and-tunneling-socks-and-port-forwarding`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Firewall logs for an outbound SSH session from a workstation to an internal host, which is unusual in most estates.
- Zeek `conn.log` for a long-lived connection carrying interactive keystroke-sized packets.
- Target logs for connections from a host that has no business role connecting to that service.
- Endpoint telemetry for `ssh -D` or `socat TCP-LISTEN` in a command line.
- Flow records for one internal source contacting many destinations in sequence, the SOCKS fan-out.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
