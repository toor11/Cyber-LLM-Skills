# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`saml-assertion-attacks`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `saml-assertion-attacks`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Signature-presence differential

**Expected differential:** a response with the ds:Signature element removed is accepted only if signatures are optional; the intact control always authenticates

```text
SAMLResponse with the ds:Signature element stripped and the same NameID
SAMLResponse with the original signed assertion intact
```

### Parser-differential probe

**Expected differential:** a response readable differently by two parsers changes the consumed Subject only if verification and extraction disagree

```text
SAMLResponse with a second saml:Assertion appended after the signed one
SAMLResponse carrying only the single signed saml:Assertion
```

### DOCTYPE acceptance check

**Expected differential:** a benign DOCTYPE accepted proves the service provider parser is not hardened against entity handling

```text
SAMLResponse prefixed with a benign DOCTYPE samlp:Response declaration
SAMLResponse with no DOCTYPE declaration at all
```

### Replay and recipient differential

**Expected differential:** resubmitting a captured assertion past its window, or to a different recipient, succeeds only if Conditions are unenforced

```text
replay the captured SAMLResponse after its NotOnOrAfter has passed
submit the captured SAMLResponse within its validity window
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
