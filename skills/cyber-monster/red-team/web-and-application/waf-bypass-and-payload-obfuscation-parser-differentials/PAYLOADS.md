# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`waf-bypass-and-payload-obfuscation-parser-differentials`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `waf-bypass-and-payload-obfuscation-parser-differentials`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Content-type container swap

**Expected differential:** the marker is blocked as urlencoded and accepted as multipart, proving a body-type coverage gap

```text
Content-Type: application/x-www-form-urlencoded (body field=wafprobe-ct)
Content-Type: multipart/form-data; boundary=wfpd (same field value wafprobe-ct)
```

### Charset remap

**Expected differential:** the alternate charset changes the origin's view of the bytes while the edge matched ASCII

```text
Content-Type: application/x-www-form-urlencoded; charset=ibm037
Content-Type: application/x-www-form-urlencoded; charset=utf-8 (control)
```

### Duplicate-parameter resolution

**Expected differential:** the origin reads the last copy while the WAF reads the first, so the marker hides in the last copy

```text
role=guest&role=wafprobe-dup (last-wins origin, first-wins edge)
role=wafprobe-dup&role=guest (reversed-order control)
```

### Chunked body opacity

**Expected differential:** the edge forwards the chunked body unparsed while the origin dechunks and reads the field

```text
Transfer-Encoding: chunked (single chunk carrying field=wafprobe-chk)
Content-Length: 20 (same field, length-delimited control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
