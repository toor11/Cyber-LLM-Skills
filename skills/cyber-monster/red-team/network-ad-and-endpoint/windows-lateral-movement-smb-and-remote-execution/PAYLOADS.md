# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`windows-lateral-movement-smb-and-remote-execution`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `windows-lateral-movement-smb-and-remote-execution`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Share and rights check

**Expected differential.** A successful `ADMIN$` listing with the credential proves both authentication and administrative rights.

```bash
netexec smb 10.20.30.20 -u Administrator -H <hash> --shares
smbclient //10.20.30.20/ADMIN$ -U 'CORP/Administrator%pass' -c 'ls'
```

## SMB configuration

**Expected differential.** Signing requirement and SMB1 availability define which sub-primitives exist.

```bash
nmap -p 445 --script smb2-security-mode,smb2-capabilities 10.20.30.20
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature,EnableSMB1Protocol
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
