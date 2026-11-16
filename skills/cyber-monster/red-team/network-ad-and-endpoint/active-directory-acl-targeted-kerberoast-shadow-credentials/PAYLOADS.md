# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-acl-targeted-kerberoast-shadow-credentials`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-acl-targeted-kerberoast-shadow-credentials`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Attribute write rights

**Expected differential.** A write ACE on the specific GUID naming a non-tier-0 trustee is the finding; a read ACE or a deny is not.

```bash
Get-Acl 'AD:CN=adm_target,OU=Privileged,DC=corp,DC=example' |
  Select-Object -ExpandProperty Access | Where-Object ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063'
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(sAMAccountName=adm_target)' msDS-KeyCredentialLink
```

## Authentication shape after installation

**Expected differential.** A 4768 with `PreAuthType 16` for an account that normally uses password pre-auth proves PKINIT was used, which is the shadow-credential signature.

```bash
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4768} -MaxEvents 50 | Select-String 'PreAuthType'
Get-ADUser adm_target -Properties msDS-KeyCredentialLink
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
