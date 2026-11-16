# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`saml-assertion-attacks-assertion-forgery`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `saml-assertion-attacks-assertion-forgery`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Unsigned-acceptance probe

**Expected differential:** a response with no signature that still authenticates proves signatures are optional; the original signed control always works

```text
hand-built SAMLResponse with NameID assessor and no ds:Signature element
the original signed SAMLResponse left unchanged
```

### Comment-truncation probe

**Expected differential:** a comment inside NameID that logs in as the truncated identity proves a canonicalise-versus-read split

```text
NameID value assessor then a SAML comment then @sp.example
NameID value assessor@sp.example with no comment
```

### Replay-window probe

**Expected differential:** resubmitting a captured assertion after NotOnOrAfter succeeds only if Conditions are unenforced

```text
resubmit the captured assertion one hour after its NotOnOrAfter
submit the captured assertion inside its NotOnOrAfter window
```

### Audience and recipient probe

**Expected differential:** an assertion whose Audience names a different service provider is accepted only if audience restriction is skipped

```text
assertion whose saml:Audience is https://other-sp.example
assertion whose saml:Audience is https://sp.example/acs
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
