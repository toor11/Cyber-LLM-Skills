# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`open-redirect`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `open-redirect`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Off-site navigation differential

**Expected differential:** the in-app path keeps the browser on-origin while the absolute host sends it off-domain, and the off-site case reverts once a path allowlist is enforced

```text
next=https://<assessor-controlled-host>/landing
next=/dashboard
```

### Scheme-relative and backslash parser forms

**Expected differential:** a `//host` or `/\host` value is treated as an authority by the browser even though the server saw it as a path, exposing a parser differential

```text
next=//<assessor-controlled-host>
next=/\<assessor-controlled-host>
```

### Location-header confirmation (no navigation)

**Expected differential:** the response Location host differs between the in-app and off-site value, confirming request control before any browser step

```text
GET /login?next=/account then read the Location response header
GET /login?next=https://<assessor-controlled-host>/ then read the Location response header
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
