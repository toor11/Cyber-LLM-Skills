# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http-request-smuggling-http2-desync`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http-request-smuggling-http2-desync`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### H2.CL length-mismatch probe (own stream)

**Expected differential:** an HTTP/2 request whose client content-length is smaller than its DATA byte count makes a trusting origin frame short and stall or diverge, versus a matched-length control that responds normally

```text
h2 request with content-length below the real DATA byte count (H2.CL mismatch probe)
h2 request with content-length equal to the DATA byte count (H2.CL control)
```

### H2.TE survival probe

**Expected differential:** a transfer-encoding chunked header sent over HTTP/2 that survives the downgrade desyncs the origin, while the same request without that header does not

```text
h2 request carrying transfer-encoding chunked through the downgrade (H2.TE probe)
h2 request with no transfer-encoding header (H2.TE control)
```

### Request-tunnelling header probe

**Expected differential:** a header or pseudo-header value containing an encoded CRLF that reaches the origin as a new request line proves tunnelling, versus a clean header value that does not

```text
h2 header value containing an embedded CRLF and a smuggled request line (tunnelling probe)
h2 header value with no line breaks (tunnelling control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
