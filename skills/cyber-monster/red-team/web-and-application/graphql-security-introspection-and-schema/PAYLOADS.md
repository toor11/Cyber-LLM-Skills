# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`graphql-security-introspection-and-schema`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `graphql-security-introspection-and-schema`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Direct introspection

**Expected differential:** the type system returns versus an introspection-disabled error

```text
{ __schema { types { name } } } as the introspection probe
{ __schema { mutationType { fields { name } } } } to list mutations
```

### Error-suggestion reconstruction

**Expected differential:** a near-miss field name yields a did-you-mean suggestion versus a generic error

```text
query a deliberately misspelled field to harvest the suggested name
query a known-good field as the suggestion baseline
```

### Targeted type enumeration

**Expected differential:** a __type query enumerates the arguments of a sensitive type versus a refusal

```text
{ __type(name: "Mutation") { fields { name args { name } } } }
compare the recovered mutation list against the client's used operations
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
