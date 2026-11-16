# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http-request-smuggling`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http-request-smuggling`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### Ambiguous-framing acceptance check (edge rejection test)

**Expected differential:** a benign request carrying both framing headers is rejected by a hardened edge and accepted by a vulnerable one; the body is a terminated empty chunk, so nothing is smuggled

```text
Content-Length: 0  +  Transfer-Encoding: chunked  with body 0 CRLF CRLF (both headers, empty terminated body)
Content-Length: 5  +  Transfer-Encoding: chunked  with body 0 CRLF CRLF (conflicting lengths, empty terminated body)
```

### Back-end timing oracle (self-connection only)

**Expected differential:** a chunked body deliberately left awaiting its terminator stalls the back end up to its read timeout for the desync case and returns promptly for the well-framed control; measured on the tester's own connection

```text
well-framed chunked body, fully terminated (control, expect prompt response)
chunked body missing its final 0-size chunk (probe, expect back-end read-timeout stall)
```

### Obfuscated Transfer-Encoding survival probe

**Expected differential:** an obfuscated TE token is stripped or honoured differently by front and back, visible as a status or timing change versus a clean chunked request

```text
Transfer-Encoding followed by a space before the colon (obfuscated header name)
two Transfer-Encoding headers, one chunked and one identity (duplicate-header obfuscation)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
