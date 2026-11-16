# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-trust-and-forest-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4769 with `ServiceName` naming a service in another domain, indicating cross-trust service access.
- Windows Security 4624 with a foreign domain in `Account Domain` on a host where that domain has no business need.
- Windows Security 5136 for a change to the `trustedDomain` object, including `trustAttributes` and direction.
- Windows Security 4776 with a foreign domain name, which records NTLM fallback across the trust.
- Directory diagnostic 1644 for enumerations of the `System` container's trust objects, the discovery pattern before trust abuse.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
