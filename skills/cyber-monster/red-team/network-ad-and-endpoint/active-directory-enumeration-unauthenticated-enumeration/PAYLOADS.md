# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`active-directory-enumeration-unauthenticated-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `active-directory-enumeration-unauthenticated-enumeration`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Anonymous LDAP

**Expected differential.** A root DSE read succeeding while a one-level search returns an authorisation error is the hardened state; a one-level search returning objects is the finding.

```bash
ldapsearch -x -H ldap://10.20.30.10 -s base -b '' namingContexts
ldapsearch -x -H ldap://10.20.30.10 -b 'DC=corp,DC=example' '(objectClass=user)' sAMAccountName
```

## Null SMB session

**Expected differential.** `NT_STATUS_ACCESS_DENIED` proves the null session is refused; a returned domain SID proves anonymous SID translation is still open.

```bash
rpcclient -U '%' -N 10.20.30.10 -c 'lsaquery'
rpcclient -U '%' -N 10.20.30.10 -c 'enumdomusers'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
