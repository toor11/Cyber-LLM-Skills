# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`service-enumeration-ldap-and-directory`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `service-enumeration-ldap-and-directory`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Pre-authentication surface

**Expected differential.** A base-scope root DSE read that succeeds proves the protocol and the contexts; a one-level search that returns objects proves anonymous data exposure.

```bash
ldapsearch -x -H ldap://10.20.30.10 -s base -b '' namingContexts supportedControl
nmap -p 389,636,3268 --script ldap-rootdse 10.20.30.10
```

## Anonymous versus authenticated visibility

**Expected differential.** The anonymous search returns zero entries while the authenticated search returns the same filter's objects; that difference is the control under test.

```bash
ldapsearch -x -H ldap://10.20.30.10 -b 'DC=corp,DC=example' -s one '(objectClass=computer)' cn
ldapsearch -x -H ldap://10.20.30.10 -D 'svc-reader@corp.example' -W -b 'DC=corp,DC=example' -s one '(objectClass=computer)' cn
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
