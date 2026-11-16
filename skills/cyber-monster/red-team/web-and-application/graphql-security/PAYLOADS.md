# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`graphql-security`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `graphql-security`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Boundary-crossing single query

**Expected differential:** a query for an unauthorized field returns data versus a resolver that refuses it

```text
query another principal's object id through a top-level field
query the same field for the caller's own id as the baseline
```

### Hidden mutation reach

**Expected differential:** a schema mutation absent from the UI executes versus a gated refusal

```text
invoke a mutation discovered in the schema but not used by the client
compare with a mutation the client normally issues
```

### Consumption signal

**Expected differential:** an aliased multiplier raises work measurably versus a cost limit that rejects it

```text
one request aliasing a cheap field several times to observe scaling
the single-field version of the same request as the baseline
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
