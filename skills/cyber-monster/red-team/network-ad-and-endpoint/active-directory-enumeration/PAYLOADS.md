# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-enumeration`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Attribute readability

**Expected differential.** The same LDAP read returning a value for one identity and access-denied for another isolates the ACL that grants it.

```bash
ldapsearch -x -H ldap://dc01 -D 'lowpriv@corp.example' -W -b 'DC=corp,DC=example' '(objectClass=msDS-GroupManagedServiceAccount)' msDS-ManagedPassword
ldapsearch -x -H ldap://dc01 -D 'lowpriv@corp.example' -W -b 'DC=corp,DC=example' '(objectClass=user)' msDS-KeyCredentialLink
```

## Collection scope

**Expected differential.** A collection that completes without error but yields no Tier-0 edge is itself the finding; a collection that errors on a naming context proves the identity lacks read on it.

```bash
bloodhound-python -d corp.example -u lowpriv -p 'pass' -ns 10.20.30.10 -c All --zip
netexec ldap 10.20.30.10 -u lowpriv -p 'pass' --query '(objectClass=domain)' distinguishedName
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
