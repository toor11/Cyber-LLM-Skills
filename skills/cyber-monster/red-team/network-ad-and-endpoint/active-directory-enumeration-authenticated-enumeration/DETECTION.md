# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-enumeration-authenticated-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4662 for `Control Access Right` on `Replicating Directory Changes` or property reads across many objects from one account.
- LDAP query volume per account: more than 5,000 object reads in 10 minutes from a single non-admin identity.
- SAMR `SamrEnumerateUsersInDomain` calls from a workstation rather than a management host, visible in RPC or EDR telemetry.
- Sysmon event 1 for collector binaries, or PowerShell 4104 script blocks referencing `Get-DomainObjectAcl` or `msDS-KeyCredentialLink`.
- Windows Security 4624 logon type 3 to many hosts from one account in a short window, the session-collection footprint.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
