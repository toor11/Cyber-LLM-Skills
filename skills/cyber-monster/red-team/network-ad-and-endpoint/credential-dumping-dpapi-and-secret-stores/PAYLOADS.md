# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`credential-dumping-dpapi-and-secret-stores`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `credential-dumping-dpapi-and-secret-stores`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Master key inventory

**Expected differential.** Multiple keys for a privileged account on a lower-tier host prove recoverable material exists there; no keys prove the account never logged on interactively.

```bash
Get-ChildItem "$env:APPDATA\Microsoft\Protect" -Force -Recurse | Select-Object FullName
Get-ChildItem 'C:\Windows\System32\Microsoft\Protect' -Force -Recurse | Select-Object FullName
```

## Stored credential presence

**Expected differential.** A Credential Manager target and blob prove a stored secret exists; decryption requires the user key, which is the precondition to state.

```bash
cmdkey /list
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Credentials" -Force
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
