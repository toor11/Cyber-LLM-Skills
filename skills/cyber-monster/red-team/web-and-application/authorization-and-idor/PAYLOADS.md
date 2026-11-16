# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authorization-and-idor`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authorization-and-idor`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Cross-account object read

**Expected differential:** another account's object id returns data under the caller's session, versus the caller's own id which returns the baseline

```text
GET /api/documents/2002  with the account-A session
GET /api/documents/1001  baseline read of the caller's own object
```

### Verb-complete access

**Expected differential:** a mutation verb on a neighbour object succeeds where only a scoped read was expected, versus a 403 on a hardened build

```text
PATCH /api/documents/2002  with the account-A session
DELETE /api/documents/2002  with the account-A session
```

### Reference-family probe

**Expected differential:** both an unguessable UUID and a parameter toggle resolve across owners, versus a scoped query that denies both

```text
GET /api/documents/by-uuid/other-owner-uuid
GET /api/documents?mine=false  ownership toggle parameter
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
