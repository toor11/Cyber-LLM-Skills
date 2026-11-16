# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`insecure-deserialization-dotnet-gadgets`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `insecure-deserialization-dotnet-gadgets`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### ViewState protection fingerprint (non-destructive)

**Expected differential:** the presence of __VIEWSTATEGENERATOR and the response to a one-byte-altered __VIEWSTATE reveal whether MAC is enforced, without forging a working payload

```text
inspect the postback for __VIEWSTATE and __VIEWSTATEGENERATOR fields (MAC fingerprint)
alter one byte of __VIEWSTATE and resend (expect MAC rejection if enforced)
```

### Remoting type-policy probe

**Expected differential:** a remoting payload of a benign type outside the whitelist is instantiated on a broad policy and rejected on a strict allowlist

```text
send a remoting message carrying a benign unexpected type (broad-policy probe)
send a remoting message carrying an expected DTO type only (policy baseline)
```

### Formatter substitution baseline

**Expected differential:** substituting a benign serialized object the app never emits changes behaviour only if the formatter resolves arbitrary types

```text
submit a forged payload of an inert unexpected .NET type (formatter substitution probe)
submit the application's own legitimate payload unchanged (formatter baseline)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
