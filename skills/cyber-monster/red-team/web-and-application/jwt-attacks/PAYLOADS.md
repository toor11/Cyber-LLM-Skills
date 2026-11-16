# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jwt-attacks`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `jwt-attacks`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Algorithm-field differential

**Expected differential:** the unmodified token is accepted, and the same token re-encoded with header alg none and the signature stripped is accepted only if the verifier trusts the header

```text
Authorization: Bearer <token re-encoded with header alg none and empty signature>
Authorization: Bearer <original unmodified token> (control)
```

### Signature-integrity oracle

**Expected differential:** flipping one signature byte must cause rejection; acceptance proves the signature is not verified at all

```text
Bearer <token with the last signature byte incremented>
Bearer <original token> (control)
```

### Claim-swap differential

**Expected differential:** changing a payload claim without re-signing is rejected by a correct verifier and accepted by a broken one

```text
Bearer <token with payload sub changed, original signature kept>
Bearer <original token re-sent> (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
