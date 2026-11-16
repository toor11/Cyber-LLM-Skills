# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`lolbins-and-signed-binary-abuse-execution-proxies`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `lolbins-and-signed-binary-abuse-execution-proxies`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Proxy availability

**Expected differential.** A binary permitted from any path with any argument proves the proxy is available; a path-constrained rule proves it is not.

```bash
Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 5 Name
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-CodeIntegrity/Operational';Id=3077} -MaxEvents 20
```

## Invocation differential

**Expected differential.** An unusual parent or a URL or ordinal argument proves the proxy was abused; a documented invocation from `System32` does not.

```bash
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational';Id=1} -MaxEvents 200 |
  Where-Object { $_.Message -match 'mshta|rundll32|regsvr32' }
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' -ErrorAction SilentlyContinue
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
