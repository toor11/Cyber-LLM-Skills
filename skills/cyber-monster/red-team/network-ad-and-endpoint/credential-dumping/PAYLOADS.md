# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`credential-dumping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `credential-dumping`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Protection state

**Expected differential.** PPL enabled and Credential Guard running proves the dump path is closed; both absent proves it is open.

```bash
Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object SecurityServicesRunning,AvailableSecurityProperties
```

## Hive readability

**Expected differential.** An ACL permitting read on the SAM hive by a non-SYSTEM principal proves the file path is available without touching LSASS.

```bash
icacls C:\Windows\System32\config\SAM
icacls C:\Windows\System32\config\SECURITY
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
