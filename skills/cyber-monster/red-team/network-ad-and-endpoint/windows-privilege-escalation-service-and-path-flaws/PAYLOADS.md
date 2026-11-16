# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-privilege-escalation-service-and-path-flaws`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-privilege-escalation-service-and-path-flaws`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Service object state

**Expected differential.** A change-config ACE for a broad group proves reconfiguration; a read-only DACL proves it does not.

```bash
sc.exe sdshow LegacyAgent
Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\LegacyAgent'
```

## Path and directory ACL

**Expected differential.** An unquoted path plus a write ACE on an intermediate directory is the finding; a quoted path is not.

```bash
Get-CimInstance Win32_Service -Filter "Name='LegacyAgent'" | Select-Object PathName,StartMode,StartName
accesschk.exe -quvwc "Users" 'C:\Program Files'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
