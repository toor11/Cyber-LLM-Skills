# Detection Signals and Blue-Team Handoff

> Sub-skill: [`credential-dumping-sam-and-ntds`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Telemetry this technique leaves behind, written as the field, event id or query shape a detection engine actually keys on. Engineering and response live in the paired Blue skill.

## Primary Observable Signals

- Windows Security 4662 with `Object Type: domainDNS` and the `Replicating Directory Changes All` GUID, from a principal that is not a domain controller.
- Directory service access auditing for `DS-Replication-Get-Changes-All` on the domain naming context, which is the direct record of a DCSync-style read.
- Windows Security 4688 for `ntdsutil`, `vssadmin create shadow` or `reg save` on a hive path, where command-line auditing is enabled.
- Sysmon event 11 for a `.hiv` or `.dit` file created in a temp directory.
- Windows Security 4672 for `SeBackupPrivilege` assigned to a process that is not a backup tool.

## Blue-Team Ownership

| Handoff Target | Purpose |
|---|---|
| [`memory-forensics-network-and-credential-artifacts`](../../../blue-team/digital-forensics/memory-forensics-network-and-credential-artifacts/SKILL.md) | Query authoring, triage logic, and hardening verification |
