# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authorization-and-idor-function-level`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authorization-and-idor-function-level`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Direct privileged route

**Expected differential:** a low-privilege session reaches the admin function, versus a 403 once the role is enforced server-side

```text
GET /api/admin/users  with a low-privilege session
POST /api/admin/users  with a low-privilege session
```

### Verb tampering

**Expected differential:** a verb not exposed in the UI is not gated, versus the exposed verb which is checked

```text
PUT /api/admin/users/42  method not exposed in the UI
DELETE /api/admin/users/42  with a low-privilege session
```

### Method-override smuggle

**Expected differential:** an override reaches the gated action, versus a stack that resolves the real method and denies it

```text
X-HTTP-Method-Override: DELETE  on a POST request
_method=PUT  body override parameter on a gated route
```

### Batch handler alignment

**Expected differential:** the permission callback recorded for an item is not the handler that runs it. Prove this from source alignment, not from a crafted nested batch.

```text
function-level batch: permission callback name equals the handler executed for that same item index
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
