# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`injection-detection-methodology-parameter-mining`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `injection-detection-methodology-parameter-mining`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Single candidate add-and-revert (query)

**Expected differential:** adding one undocumented query field changes status, length, or timing, and the change reverts when the field is removed

```text
known request plus one candidate query field such as debug set to one (add run)
known request with no added field (revert baseline)
```

### Header-binding candidate probe

**Expected differential:** an undocumented request header alters behaviour, proving the framework binds headers into the request object

```text
known request plus a candidate override header such as X-Original-URL (header add run)
known request with no candidate header (header revert baseline)
```

### Serialisation-switch candidate

**Expected differential:** a format or callback candidate changes the response serialisation, proving a content-negotiation hidden input

```text
known request plus a format candidate selecting an alternate serialisation (format add run)
known request with the default serialisation only (format revert baseline)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
