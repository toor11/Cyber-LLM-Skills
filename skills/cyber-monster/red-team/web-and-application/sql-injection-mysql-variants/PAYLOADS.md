# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection-mysql-variants`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection-mysql-variants`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### XPATH error oracle

**Expected differential:** updatexml raises an error embedding the value while the benign literal does not

```text
id=5 AND updatexml(1,concat(0x7e,(SELECT @@version)),1)
id=5 AND updatexml(1,concat(0x7e,0x61),1)
```

### SLEEP timing

**Expected differential:** the SLEEP five branch adds five seconds while the SLEEP zero branch matches baseline, repeated to clear jitter

```text
q=widget' AND SLEEP(5)-- -
q=widget' AND SLEEP(0)-- -
```

### Boolean pair with hash comment

**Expected differential:** the true predicate returns the normal set and the false predicate none, using the MySQL hash comment

```text
cat=1 AND 1=1#
cat=1 AND 1=2#
```

### Identifier-slot map probe

**Expected differential:** an unknown sort token is rejected while a known one orders rows; acceptance proves interpolation

```text
order=price&limit=5
order=__nope__&limit=5
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
