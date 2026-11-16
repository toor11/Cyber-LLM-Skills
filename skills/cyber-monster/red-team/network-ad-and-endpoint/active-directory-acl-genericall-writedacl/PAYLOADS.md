# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-acl-genericall-writedacl`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-acl-genericall-writedacl`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Effective rights on one object

**Expected differential.** A `GenericAll` or `WriteDacl` ACE naming a non-tier-0 trustee is the finding; a read-only mask is the default.

```bash
dacledit.py -action read -target 'Domain Admins' -principal lowpriv corp.example/lowpriv:pass -dc-ip 10.20.30.10
Get-Acl 'AD:CN=Domain Admins,CN=Users,DC=corp,DC=example' | Select-Object -ExpandProperty Access
```

## Inheritance and propagation

**Expected differential.** An OU ACE with container inheritance proves every child is affected, which is a larger blast radius than a single object ACE.

```bash
Get-Acl 'AD:OU=Privileged,DC=corp,DC=example' | Format-List
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(distinguishedName=OU=Privileged,DC=corp,DC=example)' nTSecurityDescriptor
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
