# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-privilege-escalation-token-and-privilege-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-privilege-escalation-token-and-privilege-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Privilege state

**Expected differential.** An enabled sensitive privilege is the finding; a held-but-disabled one is a weaker finding and must be described that way.

```bash
whoami /priv /fo csv
whoami /groups | Select-String 'Mandatory Label'
```

## Token source inventory

**Expected differential.** A local service that accepts a connection from the current account is the token source; without one the privilege has nothing to impersonate.

```bash
Get-CimInstance Win32_Service | Where-Object { $_.StartName -eq 'LocalSystem' } | Select-Object Name,PathName
netstat -ano | Select-String 'LISTENING'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
