# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`process-injection-techniques-classic-and-apc-injection`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `process-injection-techniques-classic-and-apc-injection`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Access and thread pair

**Expected differential.** The pair proves the mechanism; either event alone does not.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} -MaxEvents 40 |
  Select-String 'GrantedAccess'
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=8} -MaxEvents 40
```

## Source baseline

**Expected differential.** A source image with no cross-process history proves the access is anomalous; a debugger with a long history does not.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} -MaxEvents 500 |
  Group-Object { ($_ | Select-String 'SourceImage').Line }
Get-Process | Select-Object Name,Id,Path
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
