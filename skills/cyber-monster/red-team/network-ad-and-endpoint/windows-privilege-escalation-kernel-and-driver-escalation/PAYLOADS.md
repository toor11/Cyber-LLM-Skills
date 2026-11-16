# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-privilege-escalation-kernel-and-driver-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-privilege-escalation-kernel-and-driver-escalation`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Loaded driver inventory

**Expected differential.** A driver from a user-writable path with a valid third-party signature is the candidate; a Microsoft-signed in-box driver is not.

```bash
driverquery /v /fo csv | ConvertFrom-Csv | Select-Object 'Module Name','Path','Module Type'
Get-CimInstance Win32_SystemDriver | Where-Object { $_.PathName -like '*Users*' }
```

## Protection state

**Expected differential.** HVCI enabled plus a current blocklist proves the load would be refused; HVCI off proves it would not.

```bash
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-Table SecurityServicesRunning,VirtualizationBasedSecurityStatus
(Get-Item 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config').GetValue('VulnerableDriverBlocklistEnable')
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
