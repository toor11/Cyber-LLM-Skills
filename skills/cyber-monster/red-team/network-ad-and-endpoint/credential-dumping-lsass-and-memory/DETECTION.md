# Detection Signals and Blue-Team Handoff

> Sub-skill: [`credential-dumping-lsass-and-memory`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Sysmon event 10 for `lsass.exe` with `GrantedAccess` 0x1010 or 0x1410 from a process outside the security-product allowlist.
- Sysmon event 11 for a file ending `.dmp` created in a temporary or user-writable directory with a size above 20 MB.
- Windows Security 4656 with `Object Name` naming the LSASS process and `Access Mask` including `PROCESS_VM_READ`.
- Windows Security 4672 for `SeDebugPrivilege` on a process whose parent is a script host or office application.
- Microsoft Defender event 1121 for an attack-surface-reduction rule block on credential dumping.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) | Query authoring, triage logic, and hardening verification |
