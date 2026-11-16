---
name: http-request-smuggling-http2-desync
description: HTTP/2 desync and request tunnelling. Covers H2.CL and H2.TE downgrade desync, header injection through pseudo-headers, and tunnelling requests inside a single HTTP/2 stream. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["h2 desync", "h2.cl", "request tunnelling", "http2 smuggling"]
cwe: [CWE-444]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-33]
related: [http-request-smuggling, http-request-smuggling-cl-te-and-te-cl, http-request-smuggling-te-te-and-obfuscation, http-request-smuggling-client-side-desync]
parent: http-request-smuggling
---

# Http Request Smuggling Http2 Desync - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This variant arises where an HTTP/2 front end translates requests down to HTTP/1.1 for a back end that does not speak HTTP/2. In HTTP/2 a message length is defined by the DATA frames the server actually received, but during downgrade the front end emits an HTTP/1.1 request whose length it must reconstruct, and if it copies a client-supplied `content-length` or a chunked indication rather than counting the DATA bytes, the origin can read a different length. That is H2.CL or H2.TE desync, and it also lets a client smuggle extra request lines inside pseudo-header or header values that survive the rewrite, tunnelling a second request to the origin. The decision is made in the downgrade or rewrite layer, not in application code, and the attacker gains a smuggled prefix or a tunnelled request against a back end that trusts the front end's framing. Confirmation is a differential tied to a mismatch between the DATA-frame length and the downgraded HTTP/1.1 length, reproduced on the tester's own stream.

- **Precondition chain:** An HTTP/2 front end downgrades to an HTTP/1.1 origin, the front end reconstructs the HTTP/1.1 body length from client-supplied headers rather than from the received DATA frames, the origin connection is reused, and the length mismatch or tunnelled request is observable as a differential.
- **Readable differential:** A downgraded request whose HTTP/1.1 length matches its DATA frames versus one where a client-supplied content-length disagrees with the DATA byte count; a finding exists when the mismatched request desyncs the origin and reverts once the front end derives length from DATA frames and strips client length headers.
- **Empirical grounding:** CWE-444. PortSwigger's desync research covers HTTP/2 to HTTP/1.1 downgrade smuggling, H2.CL and H2.TE; SOURCES.md has no product CVE specific to h2 downgrade framing, so this slug stays at CWE-444 plus that research.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target profile is not yet confirmed to match HTTP/2 downgrade desync **THEN** start at parent class [`http-request-smuggling`](../http-request-smuggling/SKILL.md) first
2. **IF** the front end copies a client content-length into the downgraded request **THEN** classify as H2.CL and probe a DATA-versus-content-length mismatch
3. **IF** the front end preserves a chunked indication through the downgrade **THEN** classify as H2.TE and probe the transfer-encoding survival
4. **IF** a second request line is tunnelled inside a header or pseudo-header value **THEN** treat request tunnelling as the primary finding on the downgraded stream
5. **IF** the flaw is stream-reset accounting rather than downgrade framing **THEN** switch to [`http2-specific-attacks`](../http2-specific-attacks/SKILL.md) for the concurrency invariant
6. **IF** after downgrade the dispute is plain Content-Length versus Transfer-Encoding **THEN** switch to [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) for the HTTP/1 header precedence
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** the front end derives length from DATA frames and strips client length headers **THEN** STOP and classify as a verified non-finding because the downgrade is framing-safe

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The flaw is stream-reset accounting, not downgrade framing | [`http2-specific-attacks`](../http2-specific-attacks/SKILL.md) | Invariant is per-connection stream accounting rather than content-length or :path rewriting |
| After downgrade the dispute is plain CL versus TE | [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) | Invariant is HTTP/1 header preference once the request is on the wire |
| Need parent class methodology | [`http-request-smuggling`](../http-request-smuggling/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the downgrade path exists.** Establish that the edge negotiates HTTP/2 with the client but forwards HTTP/1.1 to the origin, because H2.CL and H2.TE require that translation step.
2. **Determine how the front end sets the HTTP/1.1 length.** Read whether the rewrite counts received DATA-frame bytes or copies a client `content-length` or transfer-encoding indication, since the copied case is the defect.
3. **Record a matched-length baseline.** Send an HTTP/2 request whose DATA byte count equals its content-length value and capture the origin status and timing, giving a reference where front end and origin agree.
4. **Craft a single length-mismatch stream.** Send one HTTP/2 request where the client content-length disagrees with the actual DATA byte count (H2.CL), or where a chunked indication survives (H2.TE), keeping any smuggled region empty.
5. **Observe the origin differential on your own stream.** A desync shows as the origin framing the request by the copied length and treating the remaining bytes as a new request, visible as a timing stall or an unexpected response on the reused origin connection.
6. **Stop condition.** Halt when the mismatch stream either (a) desyncs the origin in a way attributable to the DATA-versus-length disagreement and reverting when length is DATA-derived, (b) matches the matched-length baseline across two runs, or (c) would require a prefix that lands on another user's origin request. Case (a) confirms, (b) is a non-finding, (c) is out of scope.
7. **State what counts as proof.** Proof is a reproducible origin differential caused by a deliberate mismatch between DATA-frame length and the downgraded HTTP/1.1 length, or a tunnelled request line surviving the rewrite, on the tester's own stream. A rejected malformed frame alone is not proof.
8. **Close with the structural fix.** Make the downgrade derive the HTTP/1.1 `content-length` solely from the received DATA frames, strip any client-supplied length or transfer-encoding, reject malformed or duplicated pseudo-headers, and validate header values for embedded CRLF. Verify by replaying the mismatch stream against the patched edge.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A downgraded request whose HTTP/1.1 `content-length` equals a client-sent value, not the DATA byte count | Proves H2.CL desync where the front end trusts the client length during rewrite on any h2-to-h1 edge |
| A `transfer-encoding: chunked` indication surviving the HTTP/2 to HTTP/1.1 downgrade | Proves H2.TE desync where the chunked signal should have been dropped by the terminator |
| A CRLF sequence embedded in an HTTP/2 header value reaching the origin as a new line | Proves request tunnelling where the rewrite fails to reject header-value line breaks |
| A second request line smuggled inside a `:path` or header value after downgrade | Proves HTTP/2 request tunnelling against a back end that trusts the front end's parse |
| An origin stall only on requests whose DATA count and content-length disagree | Proves the length-mismatch oracle without reading another user's data, on the reused origin connection |
| Duplicate or malformed pseudo-headers accepted by the front end during translation | Proves weak pseudo-header validation that enables the tunnelling and desync chain |

## Worked Contrast

**Vulnerable pattern:**

```python
# Downgrades h2 to h1 but copies the client's content-length header verbatim
def downgrade(h2_request):
    headers = h2_request.headers
    body = concat(h2_request.data_frames)
    # trusts the client content-length instead of the actual DATA length
    return h1_send(headers, body)
```

**Hardened pattern:**

```python
def downgrade(h2_request):
    body = concat(h2_request.data_frames)
    headers = strip(h2_request.headers, {"content-length", "transfer-encoding"})
    # length is derived from the DATA frames the server actually received
    headers["content-length"] = str(len(body))
    if h2_request.has_pseudo_conflict() or any(b"\r\n" in v for v in headers.values()):
        raise ProtocolError("malformed pseudo-header or embedded CRLF")
    return h1_send(headers, body)
```

**Why this matters:** The vulnerable downgrade trusts a client length header, so the origin can frame the request differently than the bytes the edge received. The fix derives the HTTP/1.1 length only from the DATA frames, strips client length and transfer-encoding, and rejects embedded CRLF, so the rewrite cannot smuggle a second request.

## When It Is NOT This Issue

- **HTTP/2 end to end:** when the origin also speaks HTTP/2 there is no downgrade step and DATA frames define length at both ends.
- **Length derived from DATA frames:** a front end that recomputes `content-length` from received bytes and strips client length headers cannot be tricked by a client value.
- **Malformed frames rejected:** an edge that returns a stream error on duplicate pseudo-headers or embedded CRLF closes the tunnelling path.
- **No origin connection reuse:** if the downgraded request goes to a fresh origin connection that is closed afterward, a mismatch strands no prefix.
- **Timing noise without mismatch:** a stall that appears even when DATA count and content-length agree is latency, not an H2.CL oracle.
- **Observed against out-of-scope shared infrastructure:** a downgrade differential on a CDN edge outside the engagement is not a finding for this target.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http-request-smuggling-http2-desync` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http-request-smuggling-http2-desync` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http-request-smuggling-http2-desync
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
- [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-client-side-desync`](../http-request-smuggling-client-side-desync/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http-request-smuggling-http2-desync` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-444, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/oxdf (12), OffsecCyber (1), CYBER_CPT/pentest_partners (1), CYBER_CPT/sigmahq (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 8 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
