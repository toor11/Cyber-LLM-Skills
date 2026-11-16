# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-kerberos-attacks-delegation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4769 with `Transited Services` populated, which records that a ticket traversed a delegation hop.
- Windows Security 4624 logon type 3 on a delegation host for a privileged account, the moment a TGT becomes cacheable.
- Windows Security 5136 for a change to `msDS-AllowedToActOnBehalfOfOtherIdentity` or `msDS-AllowedToDelegateTo`, with the new value in `Attribute Value`.
- Windows Security 4704 for `SeEnableDelegationPrivilege` assignment, the right that grants delegation at all.
- Kerberos service ticket request where `ServiceName` is the same host as the requesting principal's own service, the S4U2Self shape.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`hardening-windows-and-ad-authentication-hardening`](../../../blue-team/vulnerability-and-hardening/hardening-windows-and-ad-authentication-hardening/SKILL.md) | Query authoring, triage logic, and hardening verification |
