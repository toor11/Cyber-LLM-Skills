# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`client-side-security-bypasses`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `client-side-security-bypasses`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Direct submission of a disabled or hidden value

**Expected differential:** the endpoint accepts and stores a value the form marked disabled or hidden, versus the UI which never sends it

```text
POST /profile with role=admin (field hidden in UI), read stored role
POST /order with discount_pct=90 (control disabled in UI), read accepted value
```

### Guarded-route direct call

**Expected differential:** the hidden admin endpoint returns data or performs the action when called directly, versus the SPA which never exposes the link

```text
GET /api/admin/users directly (no UI link), read response code
GET /api/reports/all directly, read whether records beyond own scope return
```

### JS-validator range bypass

**Expected differential:** an out-of-range value blocked client-side is stored when posted directly, versus the in-range value

```text
quantity_requested=1  (in-range baseline)
quantity_requested=100000  (client-blocked, posted directly)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
