---
name: http-request-smuggling
description: "Exploits disagreements between front-end and back-end HTTP parsers: CL.TE, TE.CL, TE.TE, TE.0 and H2.CL desync, including client-side desync and request tunnelling. Use when a proxy, load balancer or CDN fronts an origin server."
family: web-and-application
tier: core
triggers: ["request smuggling", "smuggling", "desync", "cl.te", "te.cl", "http desync", "request tunneling"]
cwe: [CWE-444]
owasp: [A05:2021]
attack: [T1190]
capec: [CAPEC-33]
related: [http-request-smuggling-cl-te-and-te-cl, http-request-smuggling-te-te-and-obfuscation, http-request-smuggling-http2-desync, sql-injection]
---

# Http Request Smuggling - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A request passes through at least two HTTP processors, a front-end proxy or CDN and a back-end origin, and they disagree about where one message ends and the next begins. The disagreement comes from how each parser resolves the message-framing headers, principally `Content-Length` against `Transfer-Encoding: chunked`, or from how each reads the chunk line terminators and extensions. When the two length calculations differ, the trailing bytes of one request are reinterpreted by the back end as the start of the next victim's request, which is request smuggling. The security decision is made in the framing parser, not in any application code, and the attacker gains the ability to prepend bytes to another connection's request, poison a shared cache, or bypass front-end access controls. Confirmation is a controlled timing or response differential tied to one framing variable, and the 2025 taxonomy labels the four parser-disagreement shapes TERM.EXT, EXT.TERM, TERM.SPILL, and SPILL.TERM.

- **Precondition chain:** Two chained HTTP processors parse message length by different rules, at least one accepts a request carrying ambiguous or obfuscated framing without rejecting it, the connection to the back end is reused across requests, and a timing or response difference is observable to the tester.
- **Readable differential:** A well-framed request versus one whose framing is ambiguous only at the parser layer; a finding exists when the ambiguous request produces a distinct back-end timing or response that reverts once the edge rejects conflicting framing.
- **Empirical grounding:** CWE-444 covers HTTP request smuggling. PortSwigger's August 2025 research 'HTTP/1.1 must die: the desync endgame' reclassifies parser disagreements as TERM.EXT, EXT.TERM, TERM.SPILL, and SPILL.TERM; CVE-2025-32094 (Akamai, OPTIONS plus obsolete line folding plus Expect: 100-continue) and CVE-2025-4366 (Cloudflare Pingora, pingora-core before 0.5.0) are 2025 instances.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the two tiers prefer different whole framing headers (CL versus TE) **THEN** switch to [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) (1 hop)
2. **IF** the Transfer-Encoding header is obfuscated or chunk terminators are ambiguous **THEN** switch to [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) (1 hop)
3. **IF** the front end speaks HTTP/2 and downgrades to the origin **THEN** switch to [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) (1 hop)
4. **IF** the connection to be poisoned is held by a victim's browser **THEN** switch to [`http-request-smuggling-client-side-desync`](../http-request-smuggling-client-side-desync/SKILL.md) (1 hop)
5. **IF** the disagreement is about stream concurrency rather than message framing **THEN** switch to [`http2-specific-attacks`](../http2-specific-attacks/SKILL.md) for the stream-accounting invariant
6. **IF** a smuggled prefix is stored and replayed to many users by a shared cache **THEN** also read [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) because the cache amplifies one desync
7. **IF** the disputed field is the routing Host rather than the body length **THEN** read [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) because routing identity, not framing, is at stake
8. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
9. **IF** both tiers reject conflicting or obfuscated framing and the connection is not reused **THEN** STOP and classify as a verified non-finding rather than forcing a timing guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Disagreement is about stream concurrency, not message framing | [`http2-specific-attacks`](../http2-specific-attacks/SKILL.md) | Invariant is per-connection stream accounting, not Content-Length versus Transfer-Encoding |
| A smuggled prefix is stored and replayed by a shared cache | [`web-cache-poisoning-and-deception`](../web-cache-poisoning-and-deception/SKILL.md) | Invariant is cache key integrity, which turns one desync into mass impact |
| The disputed field is the routing Host header | [`http-host-header-attacks`](../http-host-header-attacks/SKILL.md) | Invariant is routing identity, a header-trust issue rather than body framing |
| Target matches `http-request-smuggling-cl-te-and-te-cl` | [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `http-request-smuggling-te-te-and-obfuscation` | [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `http-request-smuggling-http2-desync` | [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `http-request-smuggling-client-side-desync` | [`http-request-smuggling-client-side-desync`](../http-request-smuggling-client-side-desync/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map the processor chain and the framing authority.** Identify every hop (CDN, WAF, load balancer, origin) and, for each, whether it frames a POST body by `Content-Length`, by `Transfer-Encoding: chunked`, or by counting chunk bytes. The desync lives at the first pair of hops that resolve framing differently.
2. **Classify the disagreement into one of the 2025 shapes.** Decide from observed behaviour whether a terminator is read as an extension or the reverse (TERM.EXT, EXT.TERM) or whether bytes spill past the declared length (TERM.SPILL, SPILL.TERM). Name the shape before probing so the test matches the hypothesis.
3. **Record a deterministic baseline.** Send two well-framed requests on a fresh connection and capture status, response length, and back-end timing. Any natural variation between them is your noise floor; a later differential inside that band is not evidence.
4. **Choose the safest oracle.** Prefer a back-end timing differential that only stalls your own connection over any probe that could prepend bytes to a real request. Use a visible-response differential only when timing is inconclusive, and never target a connection that carries another user's traffic.
5. **Apply one framing variable at a time.** Send a request whose only difference from the baseline is the framing construct under test (a second length header, an obfuscated TE token, or an ambiguous chunk terminator) and compare against the baseline. Keep the body benign and self-terminating.
6. **Stop condition.** Halt when the probe either (a) produces a back-end timing or response differential attributable to the framing variable and reverting when the edge rejects the construct, (b) behaves identically to the baseline across two independent runs, or (c) would require prepending bytes to a connection you do not own. Case (a) confirms, (b) is a non-finding, (c) is out of scope for authorised testing.
7. **State what counts as proof.** Proof is a reproducible differential tied to a single framing construct on your own connection, plus the parser behaviour that explains it in TERM.EXT, EXT.TERM, TERM.SPILL, or SPILL.TERM terms. A lone 400, a single slow response, or a string match is not proof.
8. **Close with the structural fix.** Make one tier the sole framing authority, reject any request that carries both `Content-Length` and `Transfer-Encoding`, reject obfuscated TE and non-CRLF chunk terminators, and normalise before forwarding. Verify by replaying the confirmation probe against the patched edge.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A request accepted with both `Content-Length` and `Transfer-Encoding: chunked` | Proves the edge does not reject ambiguous framing, the precondition for CL.TE or TE.CL desync on any proxy-fronted origin |
| A back-end stall that appears only when a chunked body is left one byte short | Proves a timing oracle for a framing disagreement without reading another user's data, usable on most reverse-proxy chains |
| An obfuscated `Transfer-Encoding` token (leading space, tab, or duplicate) surviving the front end | Proves the front and back parsers normalise TE differently, the EXT and obfuscation family named by the 2025 taxonomy |
| A chunk terminator read as a chunk extension by one tier | Proves a TERM.EXT or EXT.TERM disagreement, the exact shape behind CVE-2025-22871, CVE-2024-53868, and CVE-2024-52304 |
| Bytes past the declared chunk length consumed by one tier only | Proves a TERM.SPILL or SPILL.TERM disagreement, the shape behind CVE-2025-43859, CVE-2025-29904, and CVE-2025-4600 |
| `Expect: 100-continue` combined with obsolete line folding changing how a POST is framed | Proves the folding-plus-expect handling gap seen in CVE-2025-32094 on edge appliances |
| A cached response served to a second client that contains the first client's smuggled prefix | Proves the desync reached a shared cache, escalating a single connection to mass impact |

## Worked Contrast

**Vulnerable pattern:**

```python
# Front end forwards the request even when framing is ambiguous, guessing a length
def forward(request):
    cl = request.headers.get("Content-Length")
    te = request.headers.get("Transfer-Encoding")
    # Both present: this proxy silently trusts Content-Length and streams the body on
    body = read_body(request, int(cl)) if cl else read_chunked(request)
    return backend.send(request.line, request.headers, body)
```

**Hardened pattern:**

```python
def forward(request):
    cl = request.headers.get("Content-Length")
    te = request.headers.get("Transfer-Encoding")
    # Ambiguous framing is unparseable by definition: refuse it instead of guessing
    if cl is not None and te is not None:
        return reject(400, "both Content-Length and Transfer-Encoding present")
    if te is not None and te.strip().lower() != "chunked":
        return reject(400, "unrecognised Transfer-Encoding")
    body = read_chunked(request) if te else read_body(request, int(cl or 0))
    # Re-emit canonical framing so the back end cannot reach a different length
    return backend.send(request.line, canonical(request.headers), body)
```

**Why this matters:** The vulnerable proxy resolves ambiguous framing by guessing, so its length can differ from the origin's. The fix removes the ambiguity as a class: conflicting or unrecognised framing is rejected, and the forwarded request is re-emitted in one canonical form that both tiers must agree on.

## When It Is NOT This Issue

- **Single HTTP processor:** a server with no front proxy and a reused origin cannot desync against itself; there must be two parsers that disagree.
- **Connection never reused:** if the back end opens a fresh connection per request or closes on any anomaly, a smuggled prefix has no next request to poison.
- **Edge already rejects conflicting framing:** a 400 on any request carrying both length headers means the structural control is present, so the CL/TE theory is closed.
- **Timing noise mistaken for a stall:** a slow response that does not scale with the framing construct and does not revert when the construct is removed is jitter, not a desync oracle.
- **Lab-only reproduction:** a differential seen against a local test rig but not the in-scope chain, or against infrastructure outside authorisation, is not a reportable finding.
- **HTTP/2 end to end with no downgrade:** when both tiers speak HTTP/2 and length comes from DATA frames, classic CL/TE framing does not apply and the issue, if any, is stream-level.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http-request-smuggling` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http-request-smuggling` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http-request-smuggling
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-444 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`http-request-smuggling-cl-te-and-te-cl`](../http-request-smuggling-cl-te-and-te-cl/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-te-te-and-obfuscation`](../http-request-smuggling-te-te-and-obfuscation/SKILL.md) - Web and Application (leaf)
- [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http-request-smuggling` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-444, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 58 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (32), hackerone_disclosed_reports (12), CYBER_CPT/ctf_search (12), CYBER_CPT/gh_advisories (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 14 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
