# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-acl-targeted-kerberoast-shadow-credentials`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 5136 for a modified `msDS-KeyCredentialLink` or `servicePrincipalName`, with the new value in `Attribute Value`.
- Windows Security 4768 with `PreAuthType 16` for an account whose baseline is password pre-authentication.
- Windows Security 4769 for an SPN that has never been requested before, especially from a workstation source address.
- Windows Security 4662 for `WriteProperty` on either attribute GUID by a trustee that does not normally manage service accounts.
- Certificate services event 4886 or 4887 for a PKINIT certificate issued to an account outside its normal enrollment profile.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
