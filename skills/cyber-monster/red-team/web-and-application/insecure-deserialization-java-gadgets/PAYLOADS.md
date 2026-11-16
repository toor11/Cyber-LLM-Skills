# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`insecure-deserialization-java-gadgets`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `insecure-deserialization-java-gadgets`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### URLDNS no-op confirmation (DNS oracle)

**Expected differential:** a benign serialized object produces no lookup while a URLDNS object produces a single DNS resolution to the assessor host; the lookup reverts when a resolveClass allowlist rejects the class

```text
license=<base64 of a URLDNS object pointing at <assessor-controlled-host>>
license=<base64 of a plain java.lang.String> (control, no lookup)
```

### Serialization-magic presence probe

**Expected differential:** a body beginning with the Java magic reaches the readObject sink while a JSON body does not; a deserialization-specific error versus a clean 400 shows the sink is live

```text
Body begins with rO0AB (base64 Java serialization magic)
Body begins with { for JSON (control)
```

### Class-allowlist differential

**Expected differential:** a serialized instance of the expected type is accepted while an unexpected type is accepted only when no resolveClass filter exists; acceptance of the unexpected type proves the gap

```text
payload type = expected License object (control)
payload type = unexpected java.util.PriorityQueue (probe)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
