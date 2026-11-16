# Detection Signals and Blue-Team Handoff

> Sub-skill: [`c2-implant-and-beaconing`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Zeek `conn.log` where one source-destination pair has more than 20 connections with a coefficient of variation below 0.15.
- Proxy logs for regular small POST requests to one destination at a fixed interval.
- NetFlow alerts for a destination contacted by multiple hosts on the same schedule, indicating shared infrastructure.
- DNS logs for a fixed set of names queried at a constant interval, the domain-rotation pattern.
- TLS metadata for a destination whose certificate is reused across many names, indicating a shared backend.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`dns-and-beacon-analytics`](../../../blue-team/detection-and-monitoring/dns-and-beacon-analytics/SKILL.md) | Query authoring, triage logic, and hardening verification |
