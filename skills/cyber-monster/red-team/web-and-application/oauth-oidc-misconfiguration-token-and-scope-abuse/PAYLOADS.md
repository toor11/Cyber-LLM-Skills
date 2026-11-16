# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`oauth-oidc-misconfiguration-token-and-scope-abuse`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `oauth-oidc-misconfiguration-token-and-scope-abuse`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Cross-client audience substitution

**Expected differential:** a token issued for client A is accepted at client B's API, where audience validation would reject it

```text
Authorization: Bearer <token-aud-clientA> sent to the clientB API
Authorization: Bearer <token-aud-clientB> sent to the clientB API (control)
```

### Scope-escalation grant probe

**Expected differential:** a token-exchange request with a widened scope returns a token carrying it and the resource honours it

```text
token request scope=orders:read orders:write admin
protected call with the widened-scope token versus the baseline scope
```

### Refresh-token reuse and rotation probe

**Expected differential:** a refresh token used a second time still mints an access token, unlike a rotating single-use token

```text
grant_type=refresh_token&refresh_token=<used-once-token>
grant_type=refresh_token&refresh_token=<fresh-token> (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
