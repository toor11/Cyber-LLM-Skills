# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-recon-and-port-scanning-external-perimeter-scanning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Edge or WAF logs: one source IP emitting 4xx across more than 50 distinct paths in a minute, grouped by `client_ip`.
- Provider flow logs with `action=REJECT` counts per source, which show scanning that never reached the host.
- Certificate transparency monitoring for new SAN entries covering the scanned range, which reveals shadow exposure before a scan finds it.
- DNS query logs for high-entropy subdomain enumeration against the same zone, the usual precursor to perimeter scanning.
- Zeek `http` log with a single user agent string hitting many hosts, the signature of a perimeter sweep rather than a user.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
