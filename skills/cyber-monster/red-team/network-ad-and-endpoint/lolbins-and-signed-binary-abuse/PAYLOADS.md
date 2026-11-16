# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`lolbins-and-signed-binary-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `lolbins-and-signed-binary-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Policy state

**Expected differential.** Audit-only mode proves the control does not enforce; enforced mode proves it does.

```bash
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Select-Object CodeIntegrityPolicyEnforcementStatus
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' | Select-Object Name,Property
```

## Invocation baseline

**Expected differential.** An unusual parent or a URL argument in the command line is the finding; a normal parent with a local argument is not.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 100 |
  Where-Object { $_.Message -match 'mshta|rundll32|regsvr32|certutil' }
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
