# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`path-traversal-and-lfi-encoding-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `path-traversal-and-lfi-encoding-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Single-encode survival

**Expected differential:** a single percent-encoded traversal reads out of root where the literal ../ is blocked, exposing a validate-before-decode gap

```text
path=..%2f..%2f..%2fetc%2fhostname
path=report.txt
```

### Double-encode survival

**Expected differential:** a double-encoded traversal survives one decode and resolves after a second, where single-decode confinement blocks it

```text
path=..%252f..%252fetc%252fhostname
path=%2e%2e%2freport.txt
```

### Overlong and backslash forms

**Expected differential:** overlong UTF-8 or backslash separators reconstruct traversal past a lax decoder, where canonicalisation rejects them

```text
path=%c0%ae%c0%ae/etc/hostname
path=..%5c..%5cwindows%5cwin.ini
```

### Null-byte truncation

**Expected differential:** a null byte strips a forced extension on legacy runtimes, where a modern runtime rejects the embedded byte

```text
path=../../etc/hostname%00.png
path=avatar.png
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
