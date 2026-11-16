# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`waf-bypass-and-payload-obfuscation-encoding-layers`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `waf-bypass-and-payload-obfuscation-encoding-layers`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Decode-depth differential (benign marker)

**Expected differential:** the marker arrives decoded at the origin reflection only in the wrapped form while the plaintext form is blocked

```text
q=wafprobe-encd (plaintext control, expect block page or 200)
q=%2577afprobe-encd (single-encoded first byte)
q=%25%35%32afprobe-encd (double percent-encoded prefix)
```

### Unicode fold differential

**Expected differential:** the full-width letters fold to ASCII at the origin, proven by the origin reflecting the ASCII form while the edge saw non-ASCII

```text
name=ａｂｃwafprobe (full-width abc, folds to ascii)
name=abcwafprobe (ascii control, expect filtered if abc is signatured)
```

### Application-decoded wrapper

**Expected differential:** the app decodes the field so the signature engine never inspects the payload bytes, proven by a decode-specific error on a malformed value

```text
token=d2FmcHJvYmU= (base64 of a benign marker, decoded by app)
token=d2FmcHJvYm (truncated base64, expect decode error at origin)
```

### Overlong UTF-8 form

**Expected differential:** the origin's lenient UTF-8 decoder accepts a non-shortest-form encoding of a benign ASCII character the edge matched as raw bytes

```text
p=%c0%aewafprobe (overlong encoding of '.', benign suffix)
p=.wafprobe (ascii control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
