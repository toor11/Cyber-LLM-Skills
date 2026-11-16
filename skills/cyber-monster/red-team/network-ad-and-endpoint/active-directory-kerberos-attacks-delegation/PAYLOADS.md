# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-kerberos-attacks-delegation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-kerberos-attacks-delegation`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Delegation inventory

**Expected differential.** A host with the unconstrained flag and privileged sessions is the exploitable case; a host with no privileged logons is not.

```bash
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties userAccountControl
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(userAccountControl:1.2.840.113556.1.4.803:=524288)' sAMAccountName
```

## RBCD write rights

**Expected differential.** A target attribute naming a trustee, plus a DACL granting that trustee write, is the edge; the attribute alone is not.

```bash
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |
  Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' }
netexec ldap 10.20.30.10 -u lowpriv -p pass --query '(objectClass=computer)' msDS-AllowedToActOnBehalfOfOtherIdentity
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
