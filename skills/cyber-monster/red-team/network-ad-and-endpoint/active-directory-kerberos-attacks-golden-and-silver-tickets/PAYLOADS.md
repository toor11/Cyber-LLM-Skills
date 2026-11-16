# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-kerberos-attacks-golden-and-silver-tickets`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-kerberos-attacks-golden-and-silver-tickets`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Key age and rotation state

**Expected differential.** A `PasswordLastSet` older than the oldest backup retention window means every retained copy can still forge TGTs.

```bash
Get-ADUser krbtgt -Properties PasswordLastSet,msDS-KeyVersionNumber
repadmin /showobjmeta dc01 'CN=krbtgt,CN=Users,DC=corp,DC=example'
```

## Service-key exposure for the silver case

**Expected differential.** A service account whose password is known or crackable is the silver-ticket precondition; a gMSA with an unreadable password is not.

```bash
Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties PasswordLastSet,msDS-ManagedPasswordInterval
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(objectClass=msDS-GroupManagedServiceAccount)' sAMAccountName
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
