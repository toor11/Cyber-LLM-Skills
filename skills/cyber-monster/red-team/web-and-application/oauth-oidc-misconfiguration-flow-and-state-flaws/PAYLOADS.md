# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`oauth-oidc-misconfiguration-flow-and-state-flaws`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `oauth-oidc-misconfiguration-flow-and-state-flaws`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### State-binding omission (login CSRF)

**Expected differential:** the callback completes and establishes a session with state removed, where a bound client would reject it

```text
callback?code=<tester-code>&state= (removed for CSRF test)
callback?code=<tester-code>&state=<reused-prior-value>
```

### PKCE downgrade at token endpoint

**Expected differential:** the exchange succeeds with a verifier but no registered challenge, which S256-enforcing servers reject

```text
token: grant_type=authorization_code&code_verifier=<v>&(no challenge sent at authorize)
authorize: &code_challenge_method=plain (downgrade to plain)
```

### id_token nonce replay

**Expected differential:** an id_token with a stale or absent nonce is accepted a second time, unlike a nonce-checking client

```text
client callback replayed with the prior id_token (nonce reused)
client callback with the id_token nonce cleared
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
