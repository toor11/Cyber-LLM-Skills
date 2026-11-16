# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`saml-and-webauthn-passkey-implementation-flaws`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `saml-and-webauthn-passkey-implementation-flaws`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Challenge replay differential

**Expected differential:** a second assertion reusing the first challenge is accepted only if the challenge store is not single-use; the fresh-challenge control always succeeds

```text
POST /webauthn/assertion with clientDataJSON.challenge set to a prior ceremony value
POST /webauthn/assertion with clientDataJSON.challenge set to a freshly issued value
```

### Origin binding differential

**Expected differential:** an assertion whose clientDataJSON.origin names a foreign host is accepted only if origin is never compared server-side

```text
clientDataJSON.origin set to https://<assessor-controlled-host>
clientDataJSON.origin set to https://login.example
```

### rpIdHash binding differential

**Expected differential:** authenticatorData carrying SHA-256 of a different RP ID is accepted only if rpIdHash is not recomputed

```text
authenticatorData rpIdHash set to sha256 of <assessor-controlled-host>
authenticatorData rpIdHash set to sha256 of login.example
```

### Credential-flow distinction probe

**Expected differential:** a non-discoverable credential presented where a resident key was required is accepted only if the two flows are conflated

```text
assertion with an empty userHandle against a resident-key-required login
assertion with the bound userHandle against the same login
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
