# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`saml-assertion-attacks-signature-wrapping`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `saml-assertion-attacks-signature-wrapping`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Position-ordering variant

**Expected differential:** injecting a forged Assertion before the relocated signed one flips the consumed Subject only if selection is position-based

```text
forged saml:Assertion inserted as the first child with the signed original moved into samlp:Extensions
unmodified response with the signed assertion in its original position
```

### Duplicate-ID variant

**Expected differential:** giving the forged Assertion the same ID as the signed one changes the resolved node only if extraction is ID-based

```text
forged assertion carrying an ID equal to the signed assertion's ID
forged assertion carrying a distinct ID value
```

### Namespace-rebinding variant

**Expected differential:** swapping the saml and ds prefix bindings between the verified and consumed elements flips the subject only under a namespace parser differential

```text
signed and forged assertions using swapped namespace prefix bindings
signed and forged assertions using identical namespace prefix bindings
```

### Wrapper-position sweep

**Expected differential:** moving the signed element through ds:Object and a nested decoy locates which wrapper the reader ignores

```text
signed assertion relocated inside a ds:Object wrapper
signed assertion relocated inside a nested decoy saml:Assertion
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
