# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`process-injection-techniques`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `process-injection-techniques`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Telemetry coverage

**Expected differential.** Events 8, 10 and 25 present proves the sequence is observable; their absence proves a coverage gap.

```bash
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue | Format-List MaximumSizeInBytes,RecordCount
auditpol /get /subcategory:'Handle Manipulation'
```

## Access pair differential

**Expected differential.** A write-mask handle followed by a thread creation in the same target proves the mechanism; either alone does not.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=10} -MaxEvents 50
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=8} -MaxEvents 50
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
