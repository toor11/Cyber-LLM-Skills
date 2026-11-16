# Detection Signals and Blue-Team Handoff

> Sub-skill: [`service-enumeration-database-and-remote-access`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- MSSQL error log or extended events showing a login from an address outside the application subnet, with `is_policy_checked` in the audit row.
- Windows Security 4625 logon type 3 on the database host with `Package Name: NTLM` where Kerberos was expected.
- RDP `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` event 1149 records the source and user of each authenticated session, separating NLA failures from successes.
- Firewall or flow logs showing TCP 1433 or 3389 from user subnets to database or management tiers.
- MySQL general log or audit plugin entry for connections from a host that is not an application server, with the `ssl` column empty.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`identity-and-authentication-monitoring`](../../../blue-team/detection-and-monitoring/identity-and-authentication-monitoring/SKILL.md) | Query authoring, triage logic, and hardening verification |
