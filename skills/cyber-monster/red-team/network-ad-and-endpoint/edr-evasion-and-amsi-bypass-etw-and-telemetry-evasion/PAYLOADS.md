# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Session and channel state

**Expected differential.** A missing expected session or a stopped logging service proves the pipeline changed; both present proves it did not.

```bash
logman query -ets
Get-Service EventLog | Select-Object Status,StartType
```

## Cross-host count comparison

**Expected differential.** A host with materially fewer records than peers for the same window proves a gap; a comparable count proves none.

```bash
Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' | Select-Object RecordCount,LastWriteTime
Get-WinEvent -ListLog 'Security' | Select-Object RecordCount,LastWriteTime
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
