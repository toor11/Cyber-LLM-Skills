---
name: http-request-smuggling-cl-te-and-te-cl
description: CL.TE and TE.CL smuggling. Covers classic Content-Length and Transfer-Encoding desync, including timing-based detection and prefix poisoning to reach the next request. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["cl.te", "te.cl", "request smuggling basics", "desync detection"]
cwe: [CWE-444]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-33]
related: [http-request-smuggling, http-request-smuggling-te-te-and-obfuscation, http-request-smuggling-http2-desync, http-request-smuggling-client-side-desync]
parent: http-request-smuggling
---

# Http Request Smuggling Cl Te and Te Cl - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This is the classic two-header desync, where the front end and the back end each choose a different message-length authority on a request that carries both `Content-Length` and `Transfer-Encoding: chunked`. In CL.TE the front end frames by `Content-Length` and the origin frames by chunked encoding, so the origin treats the tail of the declared body as a fresh request line; in TE.CL the roles reverse. Because the two parsers never compare notes, bytes the front end considered part of one body become a smuggled prefix on the origin's view of the next connection user. The decision lives purely in each parser's header precedence rule, and the attacker gains a controlled prefix on another request, enabling front-end control bypass, cache poisoning, or request hijack. Confirmation is a timing stall (the TE.CL or CL.TE victim waits for chunk bytes that never arrive) or a visible response difference tied to the two-header construct.

- **Precondition chain:** A request carrying both `Content-Length` and `Transfer-Encoding: chunked` is accepted, the front end and the origin apply different precedence to those two headers, the origin connection is reused, and a timing or response differential is observable without touching another user's traffic.
- **Readable differential:** A request framed by a single header versus the same request carrying both headers with conflicting lengths; a finding exists when the dual-header request stalls or responds differently and reverts once the edge rejects requests that carry both headers.
- **Empirical grounding:** CWE-444. CVE-2025-4366 (Cloudflare Pingora, pingora-core before 0.5.0) is a 2025 Content-Length versus Transfer-Encoding desync, and CVE-2025-32094 (Akamai) chains OPTIONS, obsolete line folding, and Expect: 100-continue into the same header-precedence gap.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match classic CL/TE desync **THEN** start at parent class [`http-request-smuggling`](../http-request-smuggling/SKILL.md) first
2. **IF** both tiers accept a request with Content-Length and Transfer-Encoding together **THEN** treat the dual-header acceptance as the primary finding and build the timing differential
3. **IF** the back end waits for chunk bytes while the front end already closed the body **THEN** classify as CL.TE and use a chunk-starved timing probe to confirm
4. **IF** the front end frames by chunked while the origin trusts Content-Length **THEN** classify as TE.CL and confirm with a declared-length-shorter-than-body probe
5. **IF** the Transfer-Encoding token is obfuscated rather than simply duplicated **THEN** switch to [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) for the terminator-class parsing
6. **IF** the front end speaks HTTP/2 and downgrades to the origin **THEN** switch to [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) because length comes from DATA frames
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the edge returns 400 to any request carrying both length headers **THEN** STOP and classify as a verified non-finding because the structural control is present

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Transfer-Encoding is obfuscated or chunk terminators are ambiguous | [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) | Routes to terminator-class parsing such as TERM.EXT and SPILL.TERM rather than whole-header precedence |
| The front end speaks HTTP/2 and downgrades to the origin | [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) | Length is set by DATA frames, a different framing authority than HTTP/1 headers |
| Need parent class methodology | [`http-request-smuggling`](../http-request-smuggling/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm both a front end and an origin parse the body length.** CL.TE and TE.CL require two parsers; verify a proxy, CDN, or load balancer sits ahead of the origin and that POST bodies traverse both.
2. **Decide the precedence of each tier.** Establish whether each hop honours `Content-Length` or `Transfer-Encoding: chunked` when both are present. This single fact tells you whether to test the CL.TE or the TE.CL direction.
3. **Record a single-header baseline.** Send a well-framed POST using only one length header and capture status, length, and response time on a fresh connection, so the dual-header probe has a clean reference.
4. **Build a chunk-starved or length-short probe matching the direction.** For CL.TE, send a `Content-Length` that covers a body ending before the chunked terminator; for TE.CL, send a `Content-Length` shorter than the chunked body. Keep the smuggled region empty so nothing is prepended to a real request.
5. **Measure the back-end timing differential on your own connection.** The desynced tier waits for bytes that will not arrive, so the probe stalls toward the origin read timeout while the baseline returns promptly.
6. **Stop condition.** Halt when the probe either (a) stalls or diverges in a way attributable to the two-header construct and reverting when the edge rejects dual framing, (b) matches the single-header baseline across two runs, or (c) would require sending a prefix that lands on another user's request. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a reproducible stall or response divergence caused solely by adding the second length header, with the direction labelled CL.TE or TE.CL and the parser precedence that explains it. A single slow sample or a bare 400 is not proof.
8. **Close with the structural fix.** Reject any request carrying both `Content-Length` and `Transfer-Encoding`, strip and re-derive one authoritative length at the edge, and keep front end and origin on the same precedence rule. Verify by replaying the directional probe against the patched edge.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A POST accepted with both `Content-Length` and `Transfer-Encoding: chunked` | Proves the dual-header precondition for CL.TE and TE.CL on any origin sitting behind a proxy |
| A back-end stall when the chunked terminator is withheld but `Content-Length` is satisfied | Proves a CL.TE timing oracle where the origin frames by chunks, measurable on the tester's own connection |
| A prompt front-end response while the origin still waits on the same connection | Proves a TE.CL split where the front end frames by chunks and the origin by `Content-Length` |
| `Content-Length` that is numerically smaller than the chunked body size | Proves the length-short construct that triggers TE.CL smuggling on length-trusting origins |
| An OPTIONS request with obsolete line folding and `Expect: 100-continue` changing how the body is framed | Proves the folding-plus-expect precedence gap documented for CVE-2025-32094 on edge appliances |
| Pingora or a similar Rust proxy mis-sequencing the two length headers | Proves the CVE-2025-4366 class CL/TE handling flaw in pingora-core before 0.5.0 |

## Worked Contrast

**Vulnerable pattern:**

```python
# Origin prefers Transfer-Encoding; the front proxy already framed by Content-Length
def parse_request(sock):
    headers = read_headers(sock)
    if "transfer-encoding" in headers:        # origin path, chunked
        return read_chunked(sock)             # front end split the body on Content-Length
    return read_body(sock, int(headers["content-length"]))
```

**Hardened pattern:**

```python
def parse_request(sock):
    headers = read_headers(sock)
    has_cl = "content-length" in headers
    has_te = "transfer-encoding" in headers
    # One framing authority only; CL and TE together is rejected at both tiers
    if has_cl and has_te:
        raise FramingError("conflicting Content-Length and Transfer-Encoding")
    if has_te:
        return read_chunked(sock)
    return read_body(sock, int(headers["content-length"]))
```

**Why this matters:** The vulnerable origin silently prefers one header while the front end prefers the other, so their lengths diverge. The fix makes a request that carries both headers unframeable by definition and rejects it at both tiers, removing the precedence disagreement that CL.TE and TE.CL depend on.

## When It Is NOT This Issue

- **Only one length header ever accepted:** an edge that strips or rejects the second framing header leaves nothing for the two parsers to disagree about.
- **No proxy in front of the origin:** without two parsers in the path, there is no CL.TE or TE.CL direction to test.
- **Stall caused by a slow handler:** a route that is slow on well-framed requests too is an application latency issue, not a chunk-starved desync.
- **Edge canonicalises framing before forwarding:** if the front end re-emits one authoritative length, the origin never sees the conflicting pair.
- **Obfuscated TE rather than duplicate headers:** a leading-space or duplicate-token TE is the obfuscation variant and belongs in the terminator-class skill, not classic CL/TE.
- **Observed only against out-of-scope infrastructure:** a differential against a shared CDN edge outside the engagement scope is not a reportable finding for this target.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http-request-smuggling-cl-te-and-te-cl` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http-request-smuggling-cl-te-and-te-cl` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http-request-smuggling-cl-te-and-te-cl
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-444 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`http-request-smuggling`](../http-request-smuggling/SKILL.md) - Web and Application (core)
- [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-client-side-desync`](../http-request-smuggling-client-side-desync/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http-request-smuggling-cl-te-and-te-cl` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-444, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 3 |
| Top sources | OffsecCyber (9), CYBER_CPT/nuclei_templates (6), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 4 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
