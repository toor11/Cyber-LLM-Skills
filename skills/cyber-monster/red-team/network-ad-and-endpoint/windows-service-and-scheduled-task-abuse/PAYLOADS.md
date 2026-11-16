# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-service-and-scheduled-task-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-service-and-scheduled-task-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Object authorisation

**Expected differential.** A create-service right for a broad group proves the mechanism is available without administrative rights; a restricted DACL proves it is not.

```bash
sc.exe sdshow SCMANAME
Get-Acl 'C:\Windows\System32\Tasks' | Select-Object -ExpandProperty Access
```

## Object population

**Expected differential.** A service or task outside the known baseline proves an object was created; the baseline itself proves normal state.

```bash
Get-CimInstance Win32_Service | Select-Object Name,PathName,StartName,InstallDate | Sort-Object InstallDate -Descending | Select-Object -First 10
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | Select-Object TaskName,State
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
