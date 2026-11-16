# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`client-side-storage-and-token-theft`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `client-side-storage-and-token-theft`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Storage credential read (own session)

**Expected differential:** the console reads a live token from web storage, versus an HttpOnly cookie which returns nothing to script

```text
Object.keys(localStorage)
localStorage.getItem('access_token')
document.cookie
```

### Token replay check

**Expected differential:** the token authenticates from a separate client with no device or freshness binding, versus a bound token that is refused

```text
Authorization: Bearer <token-copied-from-localStorage>
present the same token from a clean client, read 200 versus 401
```

### Bundle secret scan

**Expected differential:** the shipped JavaScript contains a token-shaped string, versus a bundle built with an env allowlist that contains none

```text
curl -s https://target.example/static/main.js -o main.js
grep -Eo "(api|secret|token)[=:][A-Za-z0-9_-]{16,}" main.js
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
