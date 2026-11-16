# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`edr-evasion-and-amsi-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `edr-evasion-and-amsi-bypass`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Surface inventory

**Expected differential.** An empty AMSI provider list or a minimal Sysmon configuration proves a coverage gap; a populated inventory proves coverage.

```bash
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers' -ErrorAction SilentlyContinue | Select-Object PSChildName
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select-Object LogName,IsEnabled,RecordCount
```

## Protection state

**Expected differential.** Tamper protection off proves the observation layer is modifiable by a local administrator; on proves it is not.

```bash
Get-MpComputerStatus | Select-Object IsTamperProtected,AMServiceEnabled,RealTimeProtectionEnabled
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | Format-List VirtualizationBasedSecurityStatus,SecurityServicesConfigured
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
