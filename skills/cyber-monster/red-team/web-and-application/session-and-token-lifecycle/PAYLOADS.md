# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`session-and-token-lifecycle`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `session-and-token-lifecycle`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Post-logout survival

**Expected differential:** the captured identifier used after logout still authenticates only if invalidation is client-side

```text
GET /account using the session captured before calling /logout
GET /account using the session after /logout returned
```

### Post-password-change survival

**Expected differential:** the old session authenticates after a password change only if events do not propagate

```text
GET /account with the pre-change session cookie
GET /account with a session created after the change
```

### Rotation reuse

**Expected differential:** the pre-login identifier reused after login succeeds only if rotation is absent

```text
reuse the pre-authentication session id on a post-login request
use the identifier the server issued at login
```

### Cookie binding inspection

**Expected differential:** the login Set-Cookie line reveals whether Secure, HttpOnly, and SameSite bind the identifier

```text
inspect Set-Cookie on the /login response for the Secure and HttpOnly flags
compare against a Set-Cookie carrying Secure, HttpOnly, and SameSite
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
