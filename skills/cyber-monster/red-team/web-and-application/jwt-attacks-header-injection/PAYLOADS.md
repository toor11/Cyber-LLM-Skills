# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jwt-attacks-header-injection`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `jwt-attacks-header-injection`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### kid path-traversal differential

**Expected differential:** a kid pointing at a predictable or empty key file lets a token signed with that key verify, while a normal kid is the control

```text
kid=../../../../dev/null (empty-key verification)
kid=2024-rot (control)
```

### jku redirection probe

**Expected differential:** setting jku to a JWKS on the assessor host causes the server to fetch the key there only if jku is unvalidated

```text
jku=https://<assessor-controlled-host>/jwks.json
jku=https://idp.example/.well-known/jwks.json (control)
```

### embedded jwk trust probe

**Expected differential:** a self-contained jwk header carrying the attacker public key verifies the token only if the server trusts in-token keys

```text
header contains jwk with an attacker-generated RSA public key
header contains only kid, no jwk (control)
```

### x5u redirection probe

**Expected differential:** x5u pointing at an attacker-hosted certificate chain is fetched only when x5u is unrestricted

```text
x5u=https://<assessor-controlled-host>/chain.pem
x5u=https://idp.example/chain.pem (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
