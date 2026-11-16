# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`insecure-deserialization`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `insecure-deserialization`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Serialized-format fingerprint (non-destructive)

**Expected differential:** a token's leading bytes reveal a native serialization format, distinguishing a deserialization surface from an opaque or data-only token

```text
inspect a cookie for a base64 prefix of rO0AB indicating a Java object stream
inspect a value for a PHP object prefix such as O: followed by a class name length
```

### Benign typed-object substitution

**Expected differential:** replacing the legitimate token with a serialized harmless type the app never issues changes behaviour only if the deserializer resolves arbitrary types

```text
submit a serialized inert object of an unexpected type in place of the normal token
submit the application's own legitimate token unchanged (substitution baseline)
```

### Integrity-check probe

**Expected differential:** tampering with one byte of a signed token is rejected, while tampering with an unsigned token is accepted, revealing whether an integrity gate protects the deserializer

```text
flip one byte of the serialized token and resend (expect rejection if signed)
resend the unmodified serialized token (integrity baseline)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
