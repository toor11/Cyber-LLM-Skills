# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`credential-dumping-sam-and-ntds`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `credential-dumping-sam-and-ntds`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Replication rights

**Expected differential.** An ACE naming a non-DC, non-backup trustee proves domain-wide extraction is possible without local admin.

```bash
Get-Acl "AD:$((Get-ADDomain).DistinguishedName)" | Select-Object -ExpandProperty Access |
  Where-Object ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(objectClass=domain)' nTSecurityDescriptor
```

## Hive accessibility

**Expected differential.** `SeBackupPrivilege` or SYSTEM access plus an unlocked hive proves a local dump path; an access-denied save proves the lock.

```bash
Get-Acl C:\Windows\System32\config\SYSTEM | Select-Object -ExpandProperty Access
vssadmin list shadows
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
