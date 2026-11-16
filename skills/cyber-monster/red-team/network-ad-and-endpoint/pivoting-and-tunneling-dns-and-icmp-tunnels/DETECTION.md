# Detection Signals and Blue-Team Handoff

> Sub-skill: [`pivoting-and-tunneling-dns-and-icmp-tunnels`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Resolver logs for a query name longer than 100 characters or a leftmost label with entropy above 4.0.
- A sustained query rate to one parent domain above the baseline for the host, over a window of minutes.
- NS or TXT records for a subdomain that the organisation did not create, found by periodic zone audits.
- ICMP echo requests with payloads above 64 bytes at a regular interval, visible in Zeek `icmp` logs.
- DNS responses with TXT record sizes clustered near the maximum, the tunnel's return path.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
