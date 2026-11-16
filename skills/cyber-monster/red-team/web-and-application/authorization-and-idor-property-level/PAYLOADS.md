# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authorization-and-idor-property-level`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authorization-and-idor-property-level`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Privilege-flag injection

**Expected differential:** adding a role or admin flag to the body persists and reads back, versus a schema that rejects the unlisted field

```text
PATCH /api/users/me  body adds role=admin beyond the form fields
PATCH /api/users/me  body adds is_admin=true
```

### Read-only field overwrite

**Expected differential:** a server-derived field accepts a client value, versus a build that recomputes it authoritatively

```text
PATCH /api/users/me  body adds balance=100000
PATCH /api/users/me  body adds verified=true
```

### Nested property smuggle

**Expected differential:** a nested object sets a privileged key that a top-level filter missed, versus a DTO that forbids it

```text
PATCH /api/users/me  settings.tenant_id set to a foreign org
POST /api/orders  nested item.unit_price overridden
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
