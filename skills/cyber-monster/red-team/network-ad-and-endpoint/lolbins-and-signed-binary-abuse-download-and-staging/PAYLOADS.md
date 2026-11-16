# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`lolbins-and-signed-binary-abuse-download-and-staging`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `lolbins-and-signed-binary-abuse-download-and-staging`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Binary and destination policy

**Expected differential.** An unrestricted binary plus an any-destination egress rule proves staging is available; a named allowlist proves it is not.

```bash
Get-NetFirewallRule -Direction Outbound -Enabled True | Select-Object DisplayName,Action
reg query 'HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy' /s
```

## Staging evidence

**Expected differential.** A creation event in a user-writable path by a download-capable binary is the finding; a normal installer path is not.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=11} -MaxEvents 100 |
  Where-Object { $_.Message -match 'certutil|bitsadmin' }
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=22} -MaxEvents 50
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
