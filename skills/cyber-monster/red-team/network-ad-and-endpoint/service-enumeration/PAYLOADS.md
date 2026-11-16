# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`service-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Probes owned by `service-enumeration`. Each one reads state or makes a single benign authorized request: none writes, escalates, or persists. Record the benign baseline first, then compare the differential stated with the probe.

## Protocol-correct identification

**Expected differential.** A well-formed negotiate or DSE request that returns structured data proves the protocol; a bare TCP connect does not.

```bash
nmap -sV --version-intensity 2 -p 389,445,161 10.20.30.20
nmap -p 445 --script smb2-capabilities,smb2-security-mode 10.20.30.20
```

## Anonymous boundary

**Expected differential.** The same request returns data unauthenticated and access-denied after hardening, which isolates the anonymous-session control.

```bash
rpcclient -U '' -N 10.20.30.20 -c 'getdompwinfo'
ldapsearch -x -H ldap://10.20.30.20 -s base -b '' '(objectClass=*)'
```

## Usage Rules

- Run only inside the scope named in the engagement letter or lab charter.
- Change one variable per probe so the differential is attributable to one control.
- Pair every confirmed finding with the structural fix in [`SKILL.md`](SKILL.md).
