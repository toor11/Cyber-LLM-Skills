# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`session-and-token-lifecycle-revocation-gaps`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `session-and-token-lifecycle-revocation-gaps`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Post-logout replay

**Expected differential:** the captured token authorises an action after logout only if it was never revoked server-side

```text
POST /api/transfer with the token captured before /logout
POST /api/transfer with a token issued after re-login
```

### Post-password-change replay

**Expected differential:** an older session authorises after a password change only if the change does not fan out

```text
GET /api/profile with the session captured before the password change
GET /api/profile with a session created after the password change
```

### Account-disable survival

**Expected differential:** a session works after the account is disabled only if disable does not revoke

```text
GET /api/orders with the session held while an administrator disables the account
GET /api/orders with a fresh login attempt after the disable
```

### Refresh reuse

**Expected differential:** a rotated refresh token still mints access tokens only if reuse is undetected

```text
exchange the old refresh token again after it was rotated
exchange the current refresh token as the control
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
