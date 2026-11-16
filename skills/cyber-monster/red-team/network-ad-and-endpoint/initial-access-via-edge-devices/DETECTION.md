# Detection Signals and Blue-Team Handoff

> Sub-skill: [`initial-access-via-edge-devices`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Appliance authentication log forwarded to the SIEM, with failed logins from a single source exceeding a threshold.
- New local administrator account created outside the management plane, visible in the appliance's audit log.
- Appliance configuration change events, especially those altering authentication, logging or interface placement.
- Unexpected outbound connections from the appliance to the internet, which indicate command-and-control or exfiltration.
- Boot integrity or firmware measurement change reported by the appliance's own attestation, where supported.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
