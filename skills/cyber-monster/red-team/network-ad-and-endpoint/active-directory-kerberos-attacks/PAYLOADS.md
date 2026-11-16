# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-kerberos-attacks`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-kerberos-attacks`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Kerberoastable set

**Expected differential.** An SPN-bearing user account with RC4 permitted is the exploitable set; an SPN-bearing account restricted to AES is a much weaker finding.

```bash
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties servicePrincipalName,msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,servicePrincipalName,msDS-SupportedEncryptionTypes
impacket-GetUserSPNs corp.example/lowpriv:pass -dc-ip 10.20.30.10 -request
```

## Pre-authentication exceptions

**Expected differential.** A user object with `DONT_REQ_PREAUTH` proves the AS-REP path needs no credential at all.

```bash
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties userAccountControl
impacket-GetNPUsers corp.example/ -usersfile users.txt -dc-ip 10.20.30.10 -no-pass
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
