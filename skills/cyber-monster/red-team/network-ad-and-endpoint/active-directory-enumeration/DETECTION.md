# Detection Signals and Blue-Team Handoff

> Sub-skill: [`active-directory-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4662 with `Object Type` naming a user or group class and `Access Mask` including `Read Property`, repeated at high volume from one account.
- Directory service access auditing for `msDS-ManagedPassword` reads, enabled via a SACL on the gMSA object.
- NetBIOS or LDAP traffic from a workstation subnet to the domain controller outside business hours, visible in flow logs on TCP 389 and 445.
- Windows Security 4624 logon type 3 on the DC from an account that normally only logs on interactively.
- Sysmon event 1 for `SharpHound.exe` or a renamed collector with `-c All` in the command line, where Sysmon is deployed.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
