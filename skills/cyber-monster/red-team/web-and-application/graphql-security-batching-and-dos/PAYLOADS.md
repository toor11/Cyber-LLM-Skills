# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`graphql-security-batching-and-dos`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `graphql-security-batching-and-dos`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Alias multiplication

**Expected differential:** work scales with the number of aliases versus a single-field baseline

```text
one document aliasing a cheap field a small increasing number of times
the single-alias version of the same field as the baseline
```

### Query batching

**Expected differential:** an array of operations returns an array of results versus a server that refuses batching

```text
POST a JSON array of two trivial operations to confirm batching
POST a single operation object as the non-batched baseline
```

### Bounded nesting

**Expected differential:** one extra level of a cyclic relationship raises resolver work versus a depth limit that rejects it

```text
a nested selection following one cyclic relationship one level deeper
the un-nested selection of the same root field as the baseline
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
