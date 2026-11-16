# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ntlm-relay-and-coercion-relay-targets`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `ntlm-relay-and-coercion-relay-targets`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## SMB signing inventory

**Expected differential.** Hosts listed by `--gen-relay-list` are the SMB relay candidates; all others are closed for SMB.

```bash
netexec smb 10.20.30.0/24 --gen-relay-list relay-targets.txt --smb-timeout 3
nmap -p 445 --script smb2-security-mode 10.20.30.10
```

## LDAP channel binding and signing

**Expected differential.** A value of 0 or 1 on channel binding and no signing requirement proves the LDAP relay path.

```bash
reg query 'HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' /v LdapEnforceChannelBinding
ldapsearch -x -H ldap://dc01 -D 'CORP\lowpriv' -w pass -b '' -s base
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
