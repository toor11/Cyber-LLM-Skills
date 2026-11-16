# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-enumeration-authenticated-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-enumeration-authenticated-enumeration`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Attribute write rights

**Expected differential.** The descriptor shows the ACE for an unexpected trustee; the write attempt then fails after remediation, which isolates the control.

```bash
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(sAMAccountName=adm_target)' msDS-AllowedToActOnBehalfOfOtherIdentity
bloodhound-python -d corp.example -u lowpriv -p pass -ns 10.20.30.10 -c ACL,ObjectProps --zip
```

## Delegation configuration

**Expected differential.** A non-empty `msDS-AllowedToActOnBehalfOfOtherIdentity` proves RBCD is configured and names the trustees.

```bash
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(objectClass=computer)' userAccountControl
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
