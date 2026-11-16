# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jwt-attacks-algorithm-confusion`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `jwt-attacks-algorithm-confusion`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### RS256-to-HS256 confusion probe

**Expected differential:** a token HMAC-signed with the RSA public key as the secret and header alg HS256 is accepted only when the verifier allows both families with one key

```text
Bearer <token header alg HS256, HMAC keyed with the RSA public key PEM>
Bearer <original RS256 token> (control)
```

### alg:none casing probe

**Expected differential:** header alg set to none in several casings with no signature; acceptance on any casing proves the none branch is reachable

```text
Bearer <token header alg none, no signature>
Bearer <token header alg nOnE, no signature>
```

### Public-key-as-secret key check

**Expected differential:** re-signing with the published JWKS public key bytes as the HMAC secret distinguishes a verifier that keys HMAC off whatever key it holds

```text
HMAC secret = PEM of the published RS256 public key
HMAC secret = empty string (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
