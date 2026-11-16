# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authentication-bypass-forced-browsing`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authentication-bypass-forced-browsing`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Path-normalisation variance

**Expected differential:** a normalised variant returns the protected content while the canonical path returns 401 or a redirect, unauthenticated in both cases

```text
GET /Admin  case variant of the protected path
GET /admin/.  dot segment that normalises to the protected path
GET /admin%2f  encoded separator variant of the route
```

### Suffix and extension trick

**Expected differential:** appending a suffix routes to the same handler but skips the filter, versus the canonical path which is gated

```text
GET /admin.json  extension suffix on a protected route
GET /admin;/  matrix-parameter suffix on the route
```

### Alternate entry point

**Expected differential:** a secondary route or static alias serves the protected content without the filter, versus the canonical gated path

```text
GET /static/../admin  alias that resolves past the filter
GET //admin  double-slash root variant of the route
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
