# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authentication-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authentication-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Unauthenticated route reach

**Expected differential:** the protected route returns state with no credential, while a known-protected control returns 401; the difference is the missing filter

```text
GET /api/account  with no session cookie present
GET /api/account  with a deliberately expired session cookie
```

### Token verification probe

**Expected differential:** a token that is decoded-but-unsigned or alg-downgraded is accepted, while a legitimately signed token is the only one that should pass

```text
Authorization: Bearer header.payload.  with an empty signature segment
Authorization: Bearer token-with-alg-header-set-to-none
```

### Multi-step gate skip

**Expected differential:** posting the post-factor step directly yields a full session, versus the intended flow that requires the factor stage first

```text
POST /login/step2  with only the password-stage cookie present
POST /login/verify  replayed without completing the factor stage
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
