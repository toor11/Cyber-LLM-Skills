# Detection Signals and Blue-Team Handoff

> Sub-skill: [`service-enumeration-snmp-and-infrastructure`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Device ACL counters or flow logs showing UDP 161 from a subnet that is not the monitoring collector.
- Zeek `snmp` log with `pdu_type: get` and a repeated OID walk from one source address.
- Syslog from the device for SNMP authentication failures, which records the wrong community attempts.
- Configuration-change syslog showing `snmp-server community` added, the usual precursor to a monitoring gap.
- NetFlow with high UDP 161 request volume and small payloads, the shape of a community sweep rather than polling.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
