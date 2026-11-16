# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-privilege-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-privilege-escalation`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Privilege and build baseline

**Expected differential.** The privilege set and build number decide which boundaries are even candidates.

```bash
whoami /priv
systeminfo | Select-String 'OS Version|Hotfix'
```

## Writable service path

**Expected differential.** A binary path under a directory with a write ACE for a broad group is the finding; a fully restricted directory is not.

```bash
Get-CimInstance Win32_Service | Select-Object Name,PathName,StartName
accesschk.exe -quvwc "Users" 'C:\ProgramData'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
