# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `edr-evasion-and-amsi-bypass-sandbox-and-analysis-detection`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Property comparison

**Expected differential.** A property list matching published sandbox fingerprints proves the environment is detectable; a list matching production proves it is not.

```bash
Get-CimInstance Win32_ComputerSystem | Select-Object NumberOfProcessors,TotalPhysicalMemory,Model
(Get-CimInstance Win32_OperatingSystem).LastBootUpTime
```

## Driver and process artefacts

**Expected differential.** Analysis-tool drivers or processes present prove the environment reveals itself; a clean production-like list proves it does not.

```bash
driverquery /v /fo csv | Select-String -Pattern 'vmware|vbox|hyper-v|xen'
Get-Process | Where-Object { $_.Name -match 'procmon|wireshark|fiddler|x64dbg' }
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
