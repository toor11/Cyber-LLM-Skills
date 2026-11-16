# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`session-and-token-lifecycle-cookie-attribute-flaws`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `session-and-token-lifecycle-cookie-attribute-flaws`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### HttpOnly script-read differential

**Expected differential:** the document cookie interface exposes the session only when HttpOnly is absent

```text
read the document cookie interface and look for the session cookie name
compare against a cookie set with HttpOnly where it stays hidden
```

### Secure cleartext differential

**Expected differential:** the cookie is sent on a cleartext request only when Secure is absent

```text
issue a cleartext request to the same host and watch for the Cookie header
issue the equivalent encrypted request as the control
```

### SameSite cross-site send

**Expected differential:** a cross-site top-level request carries the cookie only when SameSite is None or absent

```text
trigger a cross-site navigation to an authenticated route and inspect for the session cookie
trigger the same navigation same-site as the control
```

### Domain shadowing

**Expected differential:** a cookie set from a sibling subdomain overwrites the session only when Domain is a shared parent

```text
set the session cookie from a sibling subdomain with a shared parent Domain and reload the app host
set the same cookie host-only and confirm it does not shadow
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
