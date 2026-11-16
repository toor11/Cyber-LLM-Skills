# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection-sqlite-variants`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection-sqlite-variants`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Quote boundary, token error (SQLite)

**Expected differential:** a trailing quote returns an unrecognized-token error while the benign name returns rows, reverting when bound

```text
name=widget
name=widget'
```

### Column arity via ORDER BY (SQLite)

**Expected differential:** incrementing the ordinal eventually raises an out-of-range error, fixing the column count without returning extra data

```text
order=1
order=9
```

### Heavy-query delay (SQLite, no SLEEP)

**Expected differential:** the nested randomblob expression raises elapsed time only for the heavy variant; repeat to clear jitter

```text
id=5 AND 1=(SELECT 1 WHERE randomblob(10000000) IS NOT NULL)
id=5 AND 1=(SELECT 1 WHERE randomblob(1) IS NOT NULL)
```

### Error-based JSON oracle (SQLite)

**Expected differential:** a malformed JSON path to JSON_EXTRACT raises a distinct error versus a valid path, confirming reachability without reading data

```text
path=$.name
path=$.[
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
