# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`password-cracking-and-wordlists`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `password-cracking-and-wordlists`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Hash identification

**Expected differential.** The header determines the mode; a mismatched mode produces a zero-result run that looks like a strong password.

```bash
hashid '$krb5tgs$23$*svc_sql$CORP.EXAMPLE$MSSQLSvc/sql01*$abcdef$'
head -c 40 tgs.txt
```

## Policy search space

**Expected differential.** The policy values bound the mask attack's cost; a longer minimum with a banned list removes the cheap space entirely.

```bash
Get-ADDefaultDomainPasswordPolicy
net accounts /domain
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
