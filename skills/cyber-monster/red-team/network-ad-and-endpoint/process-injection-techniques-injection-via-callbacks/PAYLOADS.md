# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`process-injection-techniques-injection-via-callbacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `process-injection-techniques-injection-via-callbacks`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Execution-without-creation correlation

**Expected differential.** An execution trace with no creation event proves a non-thread mechanism; a matching creation event proves the ordinary path.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1,3,7} -MaxEvents 100
Get-Process | Where-Object { $_.Threads.Count -gt 0 } | Select-Object -First 5 Name,Id
```

## Callback-adjacent telemetry

**Expected differential.** A populated thread-pool or kernel-callback provider proves the mechanism is observable; absence proves a coverage gap.

```bash
Get-WinEvent -ListProvider *ThreadPool* -ErrorAction SilentlyContinue
logman query providers | Select-String 'ThreadPool|Kernel-Callback'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
