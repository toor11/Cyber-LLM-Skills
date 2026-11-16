# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-persistence`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Key rotation state

**Expected differential.** A key version that has not advanced since a known compromise proves forged TGTs remain valid.

```bash
Get-ADUser krbtgt -Properties PasswordLastSet,msDS-KeyVersionNumber,Modified
repadmin /showobjmeta dc01 'CN=AdminSDHolder,CN=System,DC=corp,DC=example'
```

## ACL re-application source

**Expected differential.** An ACE on AdminSDHolder naming a non-tier-0 trustee proves it will be re-applied to every protected account.

```bash
Get-Acl 'AD:CN=AdminSDHolder,CN=System,DC=corp,DC=example' | Select-Object -ExpandProperty Access
Get-ADObject -SearchBase 'CN=AdminSDHolder,CN=System,DC=corp,DC=example' -Filter * -Properties nTSecurityDescriptor
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
