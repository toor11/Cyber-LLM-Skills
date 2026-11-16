# Detection Signals and Blue-Team Handoff

> Sub-skill: [`entra-id-and-hybrid-identity`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Entra ID audit log for `Add service principal credentials`, with the acting principal and the app id.
- Entra ID sign-in log for a device-code flow, identified by the authentication protocol and the broker client id.
- Entra ID audit log for `Add registered device` or `Add registered owner to device`, especially from an unusual location.
- Directory change event for a `userCertificate` write on a computer object, which the sync account performs routinely.
- Sign-in log for a token issued to a device that has never completed a device registration, the impersonation signature.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
