# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`sql-injection-orm-and-query-builder`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `sql-injection-orm-and-query-builder`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Identifier-slot map probe (sort or column)

**Expected differential:** a real column reorders rows while an unknown column token raises a driver error or is ignored; acceptance that reorders proves the slot is interpolated

```text
sort=total
sort=orders.total--
sort=no_such_column_xyz
```

### Raw predicate boundary (error channel)

**Expected differential:** appending a quote to a raw filter fragment flips the response to a driver parse error versus the benign fragment, reverting when bound

```text
filter=status:open
filter=status:open'
```

### Boolean fragment pair through the builder

**Expected differential:** a tautology fragment returns the owner normal rows while a contradiction returns none, with identical builder shape

```text
q=active) OR (1=1
q=active) AND (1=2
```

### Type-gated identifier list

**Expected differential:** source casts the list only inside an array check; a string shape is still concatenated. The fixed shape normalises every input to integers before the clause is built. Do not send a SQL fragment.

```text
source gate: is_array then absint, otherwise the original string is imploded into the NOT IN list
fixed gate: wp_parse_id_list normalises every shape to integers before author__not_in is concatenated
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
