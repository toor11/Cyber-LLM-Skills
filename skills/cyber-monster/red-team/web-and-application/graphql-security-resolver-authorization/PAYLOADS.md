# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`graphql-security-resolver-authorization`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `graphql-security-resolver-authorization`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Cross-account object read

**Expected differential:** account A retrieves account B's object by id versus a resolver that denies it

```text
query the target field with account B's object id while authenticated as A
query the same field with account A's own id as the baseline
```

### Client-ownership mutation

**Expected differential:** changing a client ownership field acts on another principal versus ownership taken from context

```text
mutation sending ownerId of account B while authenticated as A
mutation omitting ownerId to confirm the server uses the session identity
```

### Framework shortcut reach

**Expected differential:** the global node or an interface type returns an object the typed field would gate

```text
reach the object through the global node(id:) field instead of the typed field
reach the object through an interface type rather than its concrete type
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
