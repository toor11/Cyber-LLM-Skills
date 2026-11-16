# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection-postgres-variants`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection-postgres-variants`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Quote boundary, syntax channel (PostgreSQL)

**Expected differential:** appending a single quote yields SQLSTATE 42601 versus a clean response for the benign literal, reverting when the value is bound

```text
status=open
status=open'
```

### Boolean row-count pair (PostgreSQL)

**Expected differential:** a true predicate returns the normal set while a false predicate returns none, with identical request shape

```text
q=open' AND 1=1 --
q=open' AND 1=2 --
```

### Bounded delay (PostgreSQL, only when no other channel)

**Expected differential:** elapsed time rises only for the pg_sleep-keyed value and matches baseline otherwise; repeat three times to clear jitter

```text
id=5 AND 1=(SELECT 1 FROM pg_sleep(2))
id=5 AND 1=(SELECT 1 FROM pg_sleep(0))
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
