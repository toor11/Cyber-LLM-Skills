# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`jwt-attacks-claim-tampering`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `jwt-attacks-claim-tampering`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Expiry-window differential

**Expected differential:** a token whose exp is in the past is rejected by a verifier that checks exp; acceptance proves exp is ignored

```text
Bearer <token with exp set to a past timestamp, signature still valid>
Bearer <token with exp in the future> (control)
```

### Audience-confusion probe

**Expected differential:** a validly signed token minted for a different aud is accepted only if the resource server skips the audience check

```text
Bearer <token aud=api://other-service, signature valid>
Bearer <token aud=api://this-service> (control)
```

### Issuer-swap probe

**Expected differential:** a token with an unexpected iss but a valid signature from a shared key reveals missing issuer pinning

```text
Bearer <token iss=https://evil-idp.example, signature valid>
Bearer <token iss=https://idp.example> (control)
```

### Replay-window probe

**Expected differential:** resubmitting the same token after logout or rotation; continued acceptance shows no jti or revocation tracking

```text
Bearer <previously issued token resubmitted after logout>
Bearer <freshly issued token> (control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
