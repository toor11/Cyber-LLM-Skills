# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-lateral-movement`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-lateral-movement`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Credential applicability

**Expected differential.** A local administrator hash that also authenticates to a second host proves reuse; a failure proves unique passwords.

```bash
netexec smb 10.20.30.20 -u Administrator -H <hash> --local-group Administrators
netexec winrm 10.20.30.21 -u Administrator -H <hash> --check-proto
```

## Protocol availability

**Expected differential.** WinRM and SMB reachability per host proves which branches exist; a closed protocol removes that branch.

```bash
netexec winrm 10.20.30.20 -u Administrator -H <hash>
nmap -p 445,5985,3389 --reason 10.20.30.20
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
