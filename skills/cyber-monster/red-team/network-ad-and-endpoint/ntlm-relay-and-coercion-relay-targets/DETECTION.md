# Detection Signals and Blue-Team Handoff

> Sub-skill: [`ntlm-relay-and-coercion-relay-targets`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4624 logon type 3 on a domain controller where `Authentication Package: NTLM` and the source is not a known service.
- Windows Security 5136 for a new `msDS-AllowedToActOnBehalfOfOtherIdentity` value following an NTLM logon, the RBCD relay outcome.
- LDAP diagnostic event 2889 for an unsigned SASL or simple bind, which records the exact condition the control targets.
- Windows Security 4741 for a computer account created by a machine account, the object-creation relay outcome.
- Directory service event 3039 or a channel-binding failure event after enforcement is enabled, which shows the control working.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
