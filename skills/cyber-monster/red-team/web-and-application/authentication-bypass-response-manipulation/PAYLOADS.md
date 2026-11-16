# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`authentication-bypass-response-manipulation`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `authentication-bypass-response-manipulation`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Deny-branch data leak

**Expected differential:** the 401 or 403 response body still contains the protected fields, versus a correctly gated deny branch that returns none

```text
GET /api/profile  inspect the 401 body for account fields
POST /login  inspect the failed-login body for a dashboard payload
```

### Status-code dependence

**Expected differential:** the protected content is identical across the 200 and 401 branches, so a client trusting status alone is bypassable

```text
compare the response body bytes between the 200 and 401 branches
diff /api/me under a valid session versus missing credentials
```

### Client-flag trust

**Expected differential:** a JSON success flag set false still ships privileged state, versus a server that withholds it

```text
inspect authenticated:false responses for a populated user object
inspect allowed:false responses for an included resource body
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
