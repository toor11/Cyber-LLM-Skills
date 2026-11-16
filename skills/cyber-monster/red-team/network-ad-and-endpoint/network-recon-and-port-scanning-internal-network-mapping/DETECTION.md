# Detection Signals and Blue-Team Handoff

> Sub-skill: [`network-recon-and-port-scanning-internal-network-mapping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Zeek `conn.log`: one internal source contacting more than 40 distinct internal destinations on the same port inside 5 minutes.
- Windows Security 5156 on the target host records the allowed connection with `Source Address`, giving the east-west edge directly from host telemetry.
- Switch or firewall session-table alerts when one source opens more than 500 concurrent flows, the classic internal-scan signature.
- Sysmon event 3 with `DestinationPort` varying across a fixed destination range and a single `Image`, which ties scanning to a process rather than a host.
- DNS or LLMNR query bursts from one host for names it never resolved before, which is discovery running before the port scan.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
