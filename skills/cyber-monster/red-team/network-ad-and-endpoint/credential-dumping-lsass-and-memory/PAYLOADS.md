# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`credential-dumping-lsass-and-memory`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `credential-dumping-lsass-and-memory`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Protection state

**Expected differential.** PPL and Credential Guard together prove a dump is useless; both absent proves the path is open.

```bash
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' /v UseLogonCredential
```

## Access attempt shape

**Expected differential.** An access-denied result from a read-mask request proves PPL is enforcing; a success proves it is not.

```bash
Get-Process lsass | Select-Object Id,Path,ProtectionLevel
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} -MaxEvents 20 |
  Where-Object { $_.Message -match 'lsass' }
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
