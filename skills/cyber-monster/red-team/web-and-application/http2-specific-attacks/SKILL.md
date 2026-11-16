---
name: http2-specific-attacks
description: "Exploits HTTP/2 specific issues: pseudo-header injection, HPACK and header-size abuse, h2c upgrade misuse, rapid-reset resource exhaustion, and stream-level desync. Use when the target negotiates HTTP/2 directly or through a terminator."
family: web-and-application
tier: leaf
triggers: ["http2 attack", "h2 attack", "h2c", "rapid reset", "pseudo header injection"]
cwe: [CWE-444]
owasp: [A05:2021]
attack: []
capec: [CAPEC-33]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Http2 Specific Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

HTTP/2 multiplexes many streams over one connection and bounds concurrency with a settings limit, so a server must count how many streams are actively consuming backend work. This family abuses features unique to that model: pseudo-headers such as `:path` and `:authority` that a translation layer may mishandle, an h2c upgrade that can smuggle past a front end, HPACK and header-size handling that can be made expensive, and above all stream-reset accounting. In the MadeYouReset class the client provokes the server into sending its own RST_STREAM, and because a server-initiated reset is excluded from the active-stream count, the slot is freed while the backend handler keeps running, letting a client drive far more concurrent backend work than the limit allows. The decision lives in the connection's concurrency and reset bookkeeping, not in application code, and the attacker gains resource exhaustion or a denial of service against the origin. Confirmation is that backend work outruns the advertised stream limit under a controlled, bounded reset pattern.

- **Precondition chain:** The server negotiates HTTP/2, a stream reset (especially a server-initiated RST_STREAM) frees a concurrency slot while the backend work it started continues, no per-connection reset budget caps the pattern, and the resulting excess backend work is measurable against the advertised stream limit.
- **Readable differential:** A workload that stays within the advertised concurrent-stream limit versus one that triggers server-sent resets to free slots while backend work continues; a finding exists when backend concurrency exceeds the limit under the reset pattern and returns to the limit once resets are counted until backend completion.
- **Empirical grounding:** CWE-444 and resource-exhaustion framing. CVE-2025-8671 (MadeYouReset) excludes server-sent RST_STREAM from concurrency accounting while backend work continues; per-product CVE-2025-48989 (Apache Tomcat), CVE-2025-55163 (netty), and CVE-2025-54500 (F5 BIG-IP); prior art CVE-2023-44487 (Rapid Reset, client-sent resets).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** server-sent RST_STREAM frees a slot while the backend handler keeps running **THEN** treat the MadeYouReset accounting gap as the primary finding and bound the probe rate
2. **IF** the client floods client-sent resets to free slots **THEN** classify as the Rapid Reset prior-art pattern and compare reset counts against completions
3. **IF** a pseudo-header such as :path or :authority is mishandled during translation **THEN** treat pseudo-header handling as the surface and verify downstream parsing
4. **IF** an h2c upgrade smuggles a request past the front end **THEN** test the cleartext upgrade path before assuming the front end mediates every request
5. **IF** the request is rewritten to HTTP/1.1 with a trusted length **THEN** switch to [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) because the invariant is downgrade framing
6. **IF** pseudo-headers smuggle a second request downstream **THEN** switch to [`http-request-smuggling`](../http-request-smuggling/SKILL.md) because the invariant is message boundary integrity
7. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot directly to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** resets are counted against concurrency until backend work completes and a reset budget caps the connection **THEN** STOP and classify as a verified non-finding because the accounting is sound

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The h2 request is rewritten to HTTP/1.1 with a trusted length | [`http-request-smuggling-http2-desync`](../http-request-smuggling-http2-desync/SKILL.md) | Invariant is downgrade framing, not stream-reset concurrency accounting |
| Pseudo-headers smuggle a second request downstream | [`http-request-smuggling`](../http-request-smuggling/SKILL.md) | Invariant is message boundary integrity rather than connection resource accounting |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm HTTP/2 and read the concurrency settings.** Establish that the target negotiates HTTP/2 and record the advertised `SETTINGS_MAX_CONCURRENT_STREAMS`, because the finding is work that exceeds that bound.
2. **Identify the reset path under test.** Decide whether you are probing server-initiated resets (MadeYouReset) or client-initiated resets (Rapid Reset prior art), since the accounting gap differs and the per-product CVEs map to specific stacks.
3. **Establish a within-limit baseline.** Drive requests up to the advertised stream limit without triggering resets and record backend response times and error rates, giving a reference for normal concurrent load.
4. **Trigger slot release without ending backend work.** Send a bounded number of streams that provoke a server reset (for MadeYouReset) or that the client resets immediately after headers (for Rapid Reset), while the request still causes backend processing.
5. **Measure backend work against the limit.** Compare observed backend concurrency, latency, or error rate under the reset pattern to the within-limit baseline; the gap is the excess work the accounting failed to bound.
6. **Stop condition.** Halt when the reset pattern either (a) drives measurable backend work beyond the advertised stream limit and the excess disappears once resets are counted until completion, (b) shows no excess over the baseline across two bounded runs, or (c) would require a volume that degrades the service for real users. Case (a) confirms, (b) is a non-finding, (c) exceeds authorised, non-destructive testing.
7. **State what counts as proof.** Proof is backend concurrency or latency rising past the advertised limit under a controlled, bounded reset pattern, attributable to slots freed by resets while handlers run, with the reset origin identified. A single slow response or a raw reset count is not proof.
8. **Close with the structural fix.** Count a stream against the concurrency limit until its backend work actually completes regardless of reset origin, cap resets per connection with a budget, and close connections that exceed it. Verify by replaying the bounded reset pattern against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Backend handlers still running after the server sent RST_STREAM for their streams | Proves the MadeYouReset accounting gap where a server reset frees a slot but not the work, on any h2 server matching CVE-2025-8671 |
| Advertised `SETTINGS_MAX_CONCURRENT_STREAMS` far below observed concurrent backend work | Proves concurrency accounting is bypassed, the measurable signature of this class |
| A flood of client RST_STREAM frames immediately after HEADERS | Proves the Rapid Reset prior-art pattern (CVE-2023-44487) where client resets outpace slot reclamation |
| Tomcat, netty, or F5 BIG-IP origin showing reset-driven load spikes | Proves the per-product MadeYouReset variants CVE-2025-48989, CVE-2025-55163, and CVE-2025-54500 |
| An h2c upgrade accepted on a connection the front end believed was HTTP/1.1 | Proves a cleartext upgrade smuggling surface distinct from stream accounting |
| Pseudo-headers such as `:path` or `:authority` accepted with duplicate or malformed values | Proves weak pseudo-header validation that can feed downstream translation bugs |
| A disproportionate ratio of RST_STREAM frames to stream completions on one connection | Proves a reset-abuse pattern that a per-connection reset budget would have capped |

## Worked Contrast

**Vulnerable pattern:**

```python
# Server-sent RST_STREAM frees the concurrency slot immediately
def on_server_reset(conn, stream):
    conn.active_streams -= 1          # slot freed although backend work continues
    stream.send_rst()
    # the backend handler for this stream keeps running, now uncounted
```

**Hardened pattern:**

```python
RESET_BUDGET = 100

def on_server_reset(conn, stream):
    stream.send_rst()
    stream.mark_reset()
    # the slot is held until the backend handler actually finishes
    if stream.backend_done:
        conn.active_streams -= 1
    conn.resets_this_window += 1
    if conn.resets_this_window > RESET_BUDGET:
        conn.close("excessive stream resets")
```

**Why this matters:** The vulnerable server reclaims the concurrency slot the instant it resets a stream, so unbounded backend handlers run uncounted. The fix holds the slot until backend work completes regardless of who reset the stream and caps resets per connection, so a client can no longer drive work past the advertised limit.

## When It Is NOT This Issue

- **Resets counted until backend completion:** a server that keeps a reset stream against the limit until its handler finishes has no slot to over-allocate.
- **Reset budget enforced:** a per-connection cap that closes the connection after too many resets neutralises both MadeYouReset and Rapid Reset patterns.
- **No backend work per stream:** streams that are rejected before doing any backend work cost nothing to reset, so freeing the slot is harmless.
- **HTTP/1.1 only:** a target that does not negotiate HTTP/2 has no stream concurrency model to abuse.
- **Load test mistaken for a flaw:** backend latency under legitimate high concurrency that stays within the limit is capacity, not a reset-accounting bug.
- **Downgrade framing issue:** a content-length mismatch during h2-to-h1 translation is a desync finding, not a concurrency-accounting finding.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `http2-specific-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `http2-specific-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: http2-specific-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-444 | Mapping: A05:2021]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)
- [`csrf`](../csrf/SKILL.md) - Web and Application (core)
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`path-traversal-and-lfi`](../path-traversal-and-lfi/SKILL.md) - Web and Application (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `http2-specific-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-444`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/gh_advisories (4), CYBER_CPT/hacktricks (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
