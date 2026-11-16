# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-internals-and-api-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-internals-and-api-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Token baseline

**Expected differential.** The privilege list and integrity level define what is possible; a token without a privilege cannot exercise it regardless of tooling.

```bash
whoami /all
whoami /priv | Select-String 'Enabled'
```

## Object DACL

**Expected differential.** A service DACL granting `SERVICE_CHANGE_CONFIG` to a broad group proves reconfiguration is possible without admin rights; a restricted DACL proves it is not.

```bash
sc.exe sdshow SvcApp
Get-Acl 'HKLM:\SYSTEM\CurrentControlSet\Services\SvcApp'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
