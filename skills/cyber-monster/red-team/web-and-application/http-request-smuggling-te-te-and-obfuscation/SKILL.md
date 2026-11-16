---
name: http-request-smuggling-te-te-and-obfuscation
description: TE.TE and header obfuscation smuggling. Covers duplicate and obfuscated Transfer-Encoding headers, whitespace and case tricks, and parser differences that survive normalization. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["te.te", "obfuscated transfer encoding", "smuggling obfuscation"]
cwe: [CWE-444]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-33]
related: [http-request-smuggling, http-request-smuggling-cl-te-and-te-cl, http-request-smuggling-http2-desync, http-request-smuggling-client-side-desync]
parent: http-request-smuggling
---

# Http Request Smuggling Te Te and Obfuscation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This variant exploits how two tiers read the chunked encoding itself rather than which whole header they prefer. When both tiers nominally honour `Transfer-Encoding: chunked`, an attacker obfuscates the header or the chunk framing so that only one tier still recognises it as chunked: a leading space or tab before the colon, a duplicated or mis-cased token, an unexpected chunk extension, or a bare line feed instead of CRLF as a chunk terminator. The 2025 research names the resulting parser disagreements by which construct each side misreads, TERM.EXT, EXT.TERM, TERM.SPILL, and SPILL.TERM, where a terminator is taken for an extension, an extension is taken for a terminator, or bytes spill past the declared size. The decision is made inside the chunk tokeniser, and the attacker gains the same smuggled-prefix primitive as classic desync but through encodings a naive filter misses. Confirmation is a differential that appears only when the chunk framing is obfuscated and disappears when strict CRLF chunk parsing is enforced.

- **Precondition chain:** Both tiers accept chunked bodies, at least one tier normalises or tokenises the chunk framing more loosely than the other (obfuscated TE token, chunk extension, or non-CRLF terminator), the origin connection is reused, and the resulting disagreement is observable as a timing or response differential.
- **Readable differential:** A clean chunked request versus the same body with an obfuscated TE token or an ambiguous chunk terminator; a finding exists when the obfuscated form desyncs while the clean form does not, and the difference vanishes once strict CRLF chunk parsing rejects the construct.
- **Empirical grounding:** CWE-444. The w4ke 'Funky chunks' research (June 2025) and PortSwigger's desync endgame name the chunk-terminator classes: CVE-2025-22871 (Go net/http) is EXT.TERM, CVE-2024-53868 (Apache Traffic Server) and CVE-2024-52304 (AIOHTTP) are TERM.EXT, and CVE-2025-43859 (h11), CVE-2025-29904 (Ktor), and CVE-2025-4600 (Google Classic Application Load Balancer) are SPILL.TERM.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match TE obfuscation or chunk-terminator ambiguity **THEN** start at parent class [`http-request-smuggling`](../http-request-smuggling/SKILL.md) first
2. **IF** one tier reads a chunk terminator as a chunk extension **THEN** classify as TERM.EXT and probe against the Traffic Server and AIOHTTP shape
3. **IF** one tier reads a chunk extension as a terminator **THEN** classify as EXT.TERM and probe against the Go net/http shape
4. **IF** bytes spill past the declared chunk size on one tier only **THEN** classify as TERM.SPILL or SPILL.TERM and probe against the h11, Ktor, or Google ALB shape
5. **IF** the Transfer-Encoding header name itself is obfuscated with whitespace or duplication **THEN** treat the TE normalisation gap as the primary finding before testing terminators
6. **IF** the two tiers simply prefer different whole headers **THEN** switch to [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) because the invariant is CL-versus-TE precedence
7. **IF** the poisoning is triggered from a victim's browser **THEN** switch to [`http-request-smuggling-client-side-desync`](../http-request-smuggling-client-side-desync/SKILL.md) for the connection-reuse angle
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** both tiers parse chunks strictly with CRLF-only terminators and reject extensions **THEN** STOP and classify as a verified non-finding because the structural control is present

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The two tiers prefer different whole framing headers | [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) | Invariant is CL-versus-TE precedence, not chunk-line terminator parsing |
| The poisoning is triggered from a victim browser | [`http-request-smuggling-client-side-desync`](../http-request-smuggling-client-side-desync/SKILL.md) | Invariant moves to connection reuse in the browser, not server-tier chunk parsing |
| Need parent class methodology | [`http-request-smuggling`](../http-request-smuggling/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm both tiers accept chunked and locate each chunk tokeniser.** Verify a clean `Transfer-Encoding: chunked` body is honoured at both hops, then determine how each hop reads the chunk-size line, extensions, and terminators.
2. **Choose the obfuscation axis from observed normalisation.** Decide whether the gap is in the header name (whitespace, duplication, case) or in the chunk framing (extension handling, bare-LF versus CRLF terminators). Pick one axis so each probe isolates one construct.
3. **Name the disagreement shape.** Map the expected behaviour to TERM.EXT, EXT.TERM, TERM.SPILL, or SPILL.TERM before sending, using the research class that matches the tier software in scope.
4. **Record a clean-chunked baseline.** Send a strictly CRLF-framed chunked body and capture status, length, and origin timing on a fresh connection, so the obfuscated probe has a clean reference.
5. **Apply one obfuscation construct.** Send the same body with exactly one modification: a space before the TE colon, a duplicate TE token, a chunk extension after the size, or a bare-LF terminator, keeping any smuggled region empty.
6. **Stop condition.** Halt when the probe either (a) desyncs in a way attributable to the single obfuscation construct and reverts under strict CRLF parsing, (b) behaves identically to the clean-chunked baseline across two runs, or (c) would require a prefix that lands on another user's request. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a reproducible differential caused by one chunk-framing or TE-obfuscation construct, labelled with its TERM.EXT, EXT.TERM, TERM.SPILL, or SPILL.TERM shape and the tier that misreads it. A string match on the header or a lone 400 is not proof.
8. **Close with the structural fix.** Enforce strict chunk parsing: accept only a single lowercase `chunked` token, require CRLF terminators, reject chunk extensions and bare-LF line ends, and re-emit canonical chunks before forwarding. Verify by replaying the obfuscation probe against the patched tier.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A `Transfer-Encoding` value with a leading space or tab before the colon surviving one tier | Proves the two tiers normalise the TE header name differently, the obfuscation entry point for TE.TE desync |
| A chunk-size line carrying an extension (`; name=value`) honoured by only one parser | Proves a TERM.EXT or EXT.TERM disagreement, the shape behind CVE-2025-22871, CVE-2024-53868, and CVE-2024-52304 |
| A bare line feed used as a chunk terminator instead of CRLF | Proves the 'Funky chunks' terminator ambiguity where one tier accepts LF and the other requires CRLF |
| Trailing bytes after a declared chunk size consumed by one tier only | Proves a TERM.SPILL or SPILL.TERM spill, the shape behind CVE-2025-43859, CVE-2025-29904, and CVE-2025-4600 |
| Two `Transfer-Encoding` headers, one `chunked` and one `identity`, treated differently | Proves duplicate-header obfuscation where one tier picks chunked and the other picks identity framing |
| A Go net/http origin accepting an extension that a fronting proxy reads as a terminator | Proves the EXT.TERM class specifically mapped to CVE-2025-22871 |
| An h11 or Ktor origin consuming spilled bytes past the chunk length | Proves the SPILL.TERM class mapped to CVE-2025-43859 and CVE-2025-29904 |

## Worked Contrast

**Vulnerable pattern:**

```python
# Tolerant chunk reader: accepts bare-LF line ends and silently drops chunk extensions
def read_chunked(sock):
    body = b""
    while True:
        line = sock.readline()                # accepts \n or \r\n
        size = int(line.split(b";")[0], 16)   # chunk extension ignored, not rejected
        if size == 0:
            break
        body += sock.read(size)
        sock.readline()
    return body
```

**Hardened pattern:**

```python
def read_chunked(sock):
    body = b""
    while True:
        line = sock.readline_strict_crlf()    # a bare LF raises, only CRLF is a line
        if b";" in line:
            raise FramingError("chunk extensions not accepted")   # blocks TERM.EXT/EXT.TERM
        size = int(line, 16)
        if size == 0:
            break
        body += sock.read(size)
        if sock.read(2) != b"\r\n":
            raise FramingError("chunk not CRLF-terminated")        # blocks TERM.SPILL/SPILL.TERM
    return body
```

**Why this matters:** The tolerant reader lets a bare LF or a chunk extension mean different things to different tiers, which is exactly the obfuscation gap. The fix pins one strict grammar: CRLF-only terminators, no extensions, and a single lowercase chunked token, so no sibling parser can read the same bytes a different way.

## When It Is NOT This Issue

- **Strict chunk parsing at both tiers:** when both ends require CRLF terminators and reject extensions, an obfuscated token is simply refused and cannot desync.
- **Obfuscation stripped at the edge:** a front end that normalises `Transfer-Encoding` to a single clean token before forwarding removes the construct the origin would misread.
- **Duplicate TE both read as chunked:** if both tiers resolve two TE headers to chunked identically, there is no disagreement to exploit.
- **Single-tier deployment:** without two chunk parsers in the path, there is no TE.TE split regardless of how the header is written.
- **400 on the obfuscated form at both tiers:** a construct rejected everywhere is evidence of a working control, not a vulnerability.
- **Encoding quirk with no reused connection:** an accepted bare-LF chunk on a connection that is closed after each request has no next request to poison.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http-request-smuggling-te-te-and-obfuscation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http-request-smuggling-te-te-and-obfuscation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http-request-smuggling-te-te-and-obfuscation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-444 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`http-request-smuggling`](../http-request-smuggling/SKILL.md) - Web and Application (core)
- [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-client-side-desync`](../http-request-smuggling-client-side-desync/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http-request-smuggling-te-te-and-obfuscation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-444, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 3 |
| Distinct dataset sources | 3 |
| Top sources | hackerone_disclosed_reports (1), CYBER_CPT/gh_advisories (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
