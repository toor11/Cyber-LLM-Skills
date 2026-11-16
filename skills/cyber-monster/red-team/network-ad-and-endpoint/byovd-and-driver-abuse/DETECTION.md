# Detection Signals and Blue-Team Handoff

> Sub-skill: [`byovd-and-driver-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 6 for a driver load with a signature from a publisher not on the approved list.
- Windows Security 4697 with `Service Type` naming a kernel driver and an image path outside `System32`.
- Code integrity event 3033 or 3077 for a driver rejected by the blocklist or the App Control policy.
- Sysmon event 1 for a service control invocation creating a driver service, with the binary path in the command line.
- EDR alert on a driver load from `%TEMP%`, `%APPDATA%` or a user profile, which has no legitimate use.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
