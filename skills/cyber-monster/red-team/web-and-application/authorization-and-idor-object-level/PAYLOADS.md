# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authorization-and-idor-object-level`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authorization-and-idor-object-level`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Sequential id neighbour read

**Expected differential:** id plus one returns another owner's row, versus the caller's own id which returns the baseline

```text
GET /api/invoices/5002  with the account-A token
GET /api/invoices/5001  baseline read of the caller's own invoice
```

### UUID leakage follow-through

**Expected differential:** a UUID seen in another response resolves without ownership, versus a scoped query that denies it

```text
GET /api/invoices/uuid-seen-in-another-response
GET /files/leaked-object-uuid/download
```

### Batch and GraphQL node

**Expected differential:** a node or batch query returns unowned objects, versus a resolver that checks ownership per element

```text
POST /graphql  node(id: other-owner-global-id)
POST /api/invoices/batch  ids include neighbour rows
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
