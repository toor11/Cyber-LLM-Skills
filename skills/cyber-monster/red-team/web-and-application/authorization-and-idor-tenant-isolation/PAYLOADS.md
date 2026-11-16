# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authorization-and-idor-tenant-isolation`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authorization-and-idor-tenant-isolation`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Org-scope override

**Expected differential:** switching the org selector returns another tenant's data, versus the caller's own selector which returns the baseline

```text
X-Org-Id: tenant-b  with a tenant-a credential
GET /api/reports/42?org=tenant-b  with a tenant-a credential
```

### Shared-cache bleed

**Expected differential:** a response cached for one tenant is served to another on the same key, versus a tenant-keyed cache that is not shared

```text
GET /api/dashboard  compare the cached body across two tenant sessions
observe Age and X-Cache headers for a tenant-agnostic key
```

### Subdomain and token confusion

**Expected differential:** a token issued for one org is accepted on another org host, versus a build that re-validates the org binding

```text
Host: tenant-b.app.example  with a tenant-a bearer token
GET /api/me  org claim differs from the host tenant
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
