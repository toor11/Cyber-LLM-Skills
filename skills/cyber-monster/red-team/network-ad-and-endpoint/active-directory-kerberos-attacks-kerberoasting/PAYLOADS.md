# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-kerberos-attacks-kerberoasting`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-kerberos-attacks-kerberoasting`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Issuance and encryption type

**Expected differential.** A 0x17 ticket for a user SPN account proves the exploitable case; a 0x12 ticket proves the account is AES-restricted.

```bash
impacket-GetUserSPNs corp.example/lowpriv:pass -dc-ip 10.20.30.10 -request -outputfile tgs.txt
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769} -MaxEvents 20 |
  Where-Object { $_.Message -match '0x17' }
```

## Account attribute baseline

**Expected differential.** The attribute value predicts the ticket type; a divergence between them means domain policy is the deciding control.

```bash
Get-ADUser svc_sql -Properties servicePrincipalName,msDS-SupportedEncryptionTypes
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(sAMAccountName=svc_sql)' msDS-SupportedEncryptionTypes
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
