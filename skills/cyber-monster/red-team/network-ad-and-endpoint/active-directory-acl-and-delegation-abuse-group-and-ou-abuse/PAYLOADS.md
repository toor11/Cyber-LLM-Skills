# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-acl-and-delegation-abuse-group-and-ou-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-acl-and-delegation-abuse-group-and-ou-abuse`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Group write rights

**Expected differential.** A member-write ACE naming a non-tier-0 trustee over a group with host-level access is the finding; over a group with no access it is not.

```bash
Get-Acl 'AD:CN=Server Admins,OU=Groups,DC=corp,DC=example' | Select-Object -ExpandProperty Access
net group 'Server Admins' /domain
```

## Container scope

**Expected differential.** An OU with container-inherited write rights and Tier-0 children proves the blast radius; the same ACE on a leaf OU does not.

```bash
Get-ADObject -SearchBase 'OU=Domain Controllers,DC=corp,DC=example' -Filter * | Select-Object Name
Get-Acl 'AD:OU=Domain Controllers,DC=corp,DC=example' | Select-Object -ExpandProperty Access
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
