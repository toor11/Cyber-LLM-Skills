# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Syntax-only boundary probe (error channel)

**Expected differential:** status or error class changes versus the benign literal, and reverts when the value is bound or escaped; no rows are returned by the probe itself

```text
tenant=acme' AND '1'='2
tenant=acme' AND '1'='1
sort=created_at' -- single quote closes the identifier context
```

### Boolean row-count pair

**Expected differential:** the true-predicate request returns the normal result set while the false-predicate request returns an empty set or zero total, with identical request shape

```text
filter=active' AND 1=1 AND 'x'='x
filter=active' AND 1=2 AND 'x'='x
```

### Identifier slot map probe

**Expected differential:** an unknown sort token is rejected while a known token works; if an unknown token is accepted and reorders rows, the identifier is interpolated

```text
sort=created_at&dir=desc
sort=__unknown_column__&dir=desc
sort=created_at&dir=sideways
```

### Bounded delay check (only when no other channel exists)

**Expected differential:** elapsed time grows only for the delay-keyed literal and matches the benign baseline otherwise; repeat three times to clear jitter

```text
id=5 AND SLEEP(2)
id=5 AND SLEEP(0)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
