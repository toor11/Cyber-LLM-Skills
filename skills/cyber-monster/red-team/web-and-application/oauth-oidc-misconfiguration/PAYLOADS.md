# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`oauth-oidc-misconfiguration`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `oauth-oidc-misconfiguration`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Redirect-matching probe

**Expected differential:** an authorization request with a modified registered redirect still issues a code, while a wholly foreign redirect is rejected

```text
redirect_uri=https://app.example/oauth/callback/../evil
redirect_uri=https://app.example.attacker.test/cb
redirect_uri=https://app.example/oauth/callback (registered control)
```

### State and nonce omission probe

**Expected differential:** completing the flow with state removed still logs in, unlike a provider that fails closed on missing state

```text
authorize?...&state= (empty state)
authorize?...  (state parameter omitted entirely)
```

### PKCE downgrade probe

**Expected differential:** the token endpoint accepts a code_verifier when the authorization request carried no code_challenge, which RFC 9700 says must be rejected

```text
token: code_verifier=<v> with no prior code_challenge
authorize: code_challenge omitted, code_challenge_method omitted
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
