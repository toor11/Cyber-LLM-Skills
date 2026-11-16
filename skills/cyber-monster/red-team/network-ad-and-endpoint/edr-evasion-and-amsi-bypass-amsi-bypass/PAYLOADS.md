# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`edr-evasion-and-amsi-bypass-amsi-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `edr-evasion-and-amsi-bypass-amsi-bypass`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Provider and module path

**Expected differential.** A non-`System32` module path or an empty provider list proves the scan surface is degraded; a `System32` path with providers proves it is intact.

```bash
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers'
Get-Process powershell -Module -ErrorAction SilentlyContinue | Where-Object ModuleName -eq 'amsi.dll'
```

## Decode-versus-verdict differential

**Expected differential.** 4104 firing without a verdict proves the decode occurred and the scan did not; both firing proves the control works.

```bash
Get-WinEvent -LogName 'Microsoft-Windows-PowerShell/Operational' -MaxEvents 40 | Where-Object Id -eq 4104
Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -MaxEvents 20
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
