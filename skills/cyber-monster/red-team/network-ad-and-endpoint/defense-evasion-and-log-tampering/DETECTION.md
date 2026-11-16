# Detection Signals and Blue-Team Handoff

> Sub-skill: [`defense-evasion-and-log-tampering`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 1102 and System 104 for cleared channels, which should always alert.
- Windows Security 4719 with `Category ID` and the new setting, which records an audit policy change.
- Windows Security 1100 and System 7034 or 7035 for the logging service stopping or crashing.
- A `EventRecordID` discontinuity in the forwarded stream, detected at the collector rather than the host.
- A host whose forwarded event count for a window falls materially below its peer group median.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
