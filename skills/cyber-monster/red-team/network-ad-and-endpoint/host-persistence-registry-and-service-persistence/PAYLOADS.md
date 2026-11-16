# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`host-persistence-registry-and-service-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `host-persistence-registry-and-service-persistence`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Autostart values and ACLs

**Expected differential.** A `Run` value with an unsigned target and a write ACE for Users is the finding; a signed vendor entry with a restricted ACL is not.

```bash
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run'
Get-Acl 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Select-Object -ExpandProperty Access
```

## Service and COM targets

**Expected differential.** A service path in a user-writable directory, or a `CLSID` pointing at a user-profile DLL, proves an execution hijack; a `System32` target does not.

```bash
Get-CimInstance Win32_Service | Where-Object { $_.PathName -notlike '*System32*' -and $_.PathName -notlike '*Program Files*' }
reg query HKLM\SOFTWARE\Classes\CLSID /s /f InprocServer32
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
