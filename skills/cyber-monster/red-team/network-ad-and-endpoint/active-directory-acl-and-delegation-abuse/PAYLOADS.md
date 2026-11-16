# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-acl-and-delegation-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-acl-and-delegation-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Descriptor read for one object

**Expected differential.** The ACE naming an unexpected trustee with a write mask is the finding; read-only ACEs are the default and prove nothing.

```bash
Get-ADUser adm_target -Properties nTSecurityDescriptor |
  Select-Object -ExpandProperty nTSecurityDescriptor |
  Select-Object -ExpandProperty Access
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(sAMAccountName=adm_target)' nTSecurityDescriptor
```

## Inheritance tracing

**Expected differential.** An ACE on the OU with `ContainerInherit` proves it applies to every child object, which is larger than an ACE on one object.

```bash
Get-Acl 'AD:OU=Servers,DC=corp,DC=example' | Select-Object -ExpandProperty Access
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(distinguishedName=OU=Servers,DC=corp,DC=example)' nTSecurityDescriptor
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
