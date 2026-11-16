# Diagnostic Verification Probes and Code Patterns

> Sub-skill: [`http-request-smuggling-cl-te-and-te-cl`](SKILL.md) | Family: **Web and Application**

Non-destructive verification probes owned by `http-request-smuggling-cl-te-and-te-cl`. Record a benign baseline first; every class below is chosen so the response differs only when the weakness is present.

## Verification Classes

### CL.TE chunk-starved timing probe (self-connection)

**Expected differential:** with the origin framing by chunks, a body that satisfies Content-Length but omits the chunked terminator stalls the origin until its read timeout, while the single-header control returns promptly

```text
Content-Length covers the body; chunked section omits its 0-size terminator (CL.TE stall probe)
single Content-Length, fully delivered body (CL.TE control, prompt response)
```

### TE.CL length-short probe (self-connection)

**Expected differential:** with the origin trusting Content-Length, a declared length shorter than the chunked body leaves trailing bytes the origin ignores, visible as a status or timing divergence from the chunked-only control

```text
Transfer-Encoding chunked body with a Content-Length shorter than its size (TE.CL probe)
Transfer-Encoding chunked body only, correct terminator (TE.CL control)
```

### Expect and line-folding precedence probe

**Expected differential:** an OPTIONS request using obsolete line folding plus Expect: 100-continue frames differently across tiers, matching the CVE-2025-32094 shape, compared against a clean OPTIONS baseline

```text
OPTIONS request with a folded header continuation line and Expect: 100-continue (folding probe)
OPTIONS request with no folding and no Expect header (folding control)
```

## Usage Rules

- Send one probe class at a time and keep the benign control request identical in every other respect.
- Stop at the first differential that proves the invariant is missing; do not escalate within the same request.
- Every confirmed class maps to the structural remediation in [`SKILL.md`](SKILL.md).
