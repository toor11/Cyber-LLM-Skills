# Detection Signals and Blue-Team Handoff

> Sub-skill: [`firewall-and-segmentation-testing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Firewall or security-group `REJECT` counters rising for one source-destination pair, which records the rule doing its job.
- Zeek `conn.log` with `conn_state: S0` repeated from one source to many ports, the signature of a blocked probe.
- Cloud flow logs with `action=DENY` and the matched rule id, which names the control rather than just the address.
- IPS alerts for protocol tunnelling over an allowed port, the case where the rule inspected headers only.
- State-table utilisation alarms on the firewall during a probe, which is the availability risk the stop condition exists for.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
