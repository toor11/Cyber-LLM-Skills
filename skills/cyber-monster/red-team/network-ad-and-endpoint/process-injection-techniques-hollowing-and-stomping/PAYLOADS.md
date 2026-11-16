# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`process-injection-techniques-hollowing-and-stomping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `process-injection-techniques-hollowing-and-stomping`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Image tampering events

**Expected differential.** Event 25 for a high-value process proves a modification; no event and no mismatch proves integrity.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=25} -MaxEvents 20
Get-Process | Where-Object { $_.Modules.Count -gt 0 } | Select-Object -First 5 Name,Id
```

## Module hash comparison

**Expected differential.** A memory hash differing from the disk hash proves tampering for that module; equality proves integrity.

```bash
Get-FileHash C:\Windows\System32\ntdll.dll -Algorithm SHA256
Get-Process lsass | Select-Object -ExpandProperty Modules | Select-Object ModuleName,FileName
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
