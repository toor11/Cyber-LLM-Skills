# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http-request-smuggling-te-te-and-obfuscation`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http-request-smuggling-te-te-and-obfuscation`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### TE header-name obfuscation survival

**Expected differential:** an obfuscated Transfer-Encoding name is honoured by one tier and ignored by the other, visible as a status or timing change versus a clean chunked request

```text
Transfer-Encoding with a single space inserted before the colon (header-name obfuscation)
Transfer-Encoding header repeated twice, values chunked then identity (duplicate-token obfuscation)
```

### Chunk-extension disagreement probe (TERM.EXT / EXT.TERM)

**Expected differential:** a chunk-size line carrying an extension is read as part of the size by one tier and as a terminator by the other, producing a differential that a clean size line does not

```text
chunk size line followed by a semicolon extension such as size;pad=0 (extension probe)
chunk size line with no extension, CRLF terminated (extension control)
```

### Terminator ambiguity probe (Funky chunks, SPILL.TERM)

**Expected differential:** a bare LF terminator or a spilled byte past the declared size desyncs the lenient tier while the CRLF control stays well framed

```text
chunk body terminated with a bare LF instead of CRLF (bare-LF terminator probe)
chunk body with one extra byte after the declared size before CRLF (spill probe)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
