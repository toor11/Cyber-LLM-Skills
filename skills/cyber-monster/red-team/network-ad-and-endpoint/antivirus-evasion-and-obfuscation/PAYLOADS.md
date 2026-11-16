# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`antivirus-evasion-and-obfuscation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `antivirus-evasion-and-obfuscation`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Control instrumentation

**Expected differential.** Script-block logging enabled plus ASR rules in block mode proves the boundary is instrumented; neither proves it is not.

```bash
Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
Get-MpPreference | Select-Object AttackSurfaceReductionRules_Ids,AttackSurfaceReductionRules_Actions
```

## Decoded-text evidence

**Expected differential.** A 4104 event containing the decoded probe string proves the scanner sees decoded content; no event proves it does not.

```bash
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 50 |
  Where-Object { $_.Id -eq 4104 }
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 20 | Where-Object Id -in 1116,1117
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
