# Detection Signals and Blue-Team Handoff

> Sub-skill: [`pivoting-and-tunneling`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Firewall or proxy logs for a long-lived outbound connection from a workstation to one external address.
- Zeek `conn.log` for a single flow carrying a large byte count in both directions over hours, the tunnel signature.
- NetFlow for internal hosts contacting many destinations from one source, the pivot's fan-out.
- Endpoint telemetry for a tunnelling binary or an SSH client with `-D` in the command line.
- Egress alerts for HTTP requests with an `Upgrade: websocket` header to a non-sanctioned destination.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
