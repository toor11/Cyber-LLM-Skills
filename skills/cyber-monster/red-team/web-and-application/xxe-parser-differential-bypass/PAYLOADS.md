# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`xxe-parser-differential-bypass`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `xxe-parser-differential-bypass`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Blocked baseline (expected charset)

**Expected differential:** a straightforward UTF-8 DOCTYPE is rejected by the check, establishing that the control is present before any bypass

```text
xxepd utf-8 body: <!DOCTYPE d [<!ENTITY m SYSTEM "file:///tmp/xxepd-marker.txt">]><d>&m;</d>  (expect blocked)
```

### Charset differential (UTF-16)

**Expected differential:** the same document encoded as UTF-16 passes the raw-byte screen yet is parsed as a DTD, dereferencing the benign marker

```text
xxepd re-encode the same DOCTYPE document as UTF-16LE with a BOM and resubmit (expect it passes the screen)
```

### Grammar differential (XInclude)

**Expected differential:** an xi:include reaches a benign marker where DOCTYPE entities are blocked, proving a non-entity inclusion path

```text
<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///tmp/xxepd-xi-marker.txt" parse="text"/></root>
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
