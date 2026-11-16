# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-certificate-services-esc1-through-esc4`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-certificate-services-esc1-through-esc4`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Template condition set

**Expected differential.** Supply-subject plus client-auth plus no approval proves ESC1; any one missing changes the class.

```bash
certipy find -u lowpriv@corp.example -p pass -dc-ip 10.20.30.10 -vulnerable -enabled -stdout
Get-ADObject -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp' -Filter {cn -eq 'Corp-User'} -Properties *
```

## Enrollment rights

**Expected differential.** An `Enroll` ACE naming Domain Users proves reachability; a template restricted to a named group narrows the exposure.

```bash
certipy find -u lowpriv@corp.example -p pass -dc-ip 10.20.30.10 -show-adcs -stdout
Get-Acl 'AD:CN=Corp-User,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=corp'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
