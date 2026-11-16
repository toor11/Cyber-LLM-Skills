# Detection Signals and Blue-Team Handoff

> Sub-skill: [`credential-dumping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 10 targeting `lsass.exe` with `GrantedAccess` 0x1010, 0x1410 or 0x1FFFFF, excluding known security products.
- Windows Security 4656 and 4663 for a handle to `lsass.exe` from an unexpected principal, when object access auditing is enabled.
- Sysmon event 11 for a `.dmp` file created in `%TEMP%`, `%WINDIR%\Temp` or a user profile, with a size consistent with LSASS.
- Windows Security 4672 for `SeDebugPrivilege` assigned to a process that is not a known administrative tool.
- Sysmon event 6 for a driver load immediately before LSASS access, the BYOVD route past PPL.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) | Query authoring, triage logic, and hardening verification |
