---
name: waf-bypass-and-payload-obfuscation
description: Bypasses web application firewalls and input filters with encoding layers, comment and whitespace tricks, case and keyword splitting, polyglots, HTTP parameter pollution, chunked and unusual transports, and rule-specific evasions. Use when a payload is blocked or sanitized and the underlying flaw is still suspected.
family: web-and-application
tier: core
triggers: ["waf bypass", "bypass waf", "filter bypass", "payload obfuscation", "firewall evasion", "blocked payload"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-13]
related: [waf-bypass-and-payload-obfuscation-encoding-layers, waf-bypass-and-payload-obfuscation-comment-and-whitespace, waf-bypass-and-payload-obfuscation-parser-differentials, sql-injection]
---

# WAF Bypass and Payload Obfuscation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **core** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

A WAF inspects a reconstruction of the request and applies signatures to the content it manages to parse, so a bypass exists when the WAF and the origin disagree about how to parse the request container and the malicious content ends up somewhere the WAF never looks. The WAFFLED research shows this at the container level: the attacker mutates the envelope, the multipart boundary, the content-type, the parameter encoding, or the transfer framing, rather than the payload, and because most sites accept urlencoded and multipart bodies interchangeably, the origin parses content the WAF discarded. The decision point is whether the WAF parser and the origin parser agree on field boundaries and encoding. The attacker lands an otherwise-signatured payload past the filter unchanged. Confirmation is that the identical payload is blocked in a plain container and allowed in a mutated container while the origin still executes it.

- **Precondition chain:** A WAF signatures request content, the WAF and the origin parse the request container differently, and the origin reconstructs the malicious content from a container the WAF mislabeled or skipped.
- **Readable differential:** Send the same payload in a plain container versus a mutated container such as an alternate content-type, a crafted multipart boundary, or a duplicated parameter; a bypass exists when the plain form is blocked and the mutated form reaches and is parsed by the origin, and it closes when the WAF and origin normalize the container identically.
- **Empirical grounding:** CWE-693 Protection Mechanism Failure and CAPEC-13. The WAFFLED research (arXiv 2503.10846) documents 1,207 container-level parsing bypasses across AWS, Azure, Cloud Armor, Cloudflare, and ModSecurity, including the finding that over ninety percent of sites accept urlencoded and multipart bodies interchangeably.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target specifically involves encoding layers such as URL, hex, unicode, or double-encoding **THEN** switch to [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) (1 hop)
2. **IF** the target specifically involves comments and whitespace to split keywords **THEN** switch to [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](../waf-bypass-and-payload-obfuscation-comment-and-whitespace/SKILL.md) (1 hop)
3. **IF** the target specifically involves parser differentials between the WAF and the origin **THEN** switch to [`waf-bypass-and-payload-obfuscation-parser-differentials`](../waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) (1 hop)
4. **IF** the target specifically involves a rule-specific evasion for one vendor **THEN** switch to [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](../waf-bypass-and-payload-obfuscation-rule-specific-evasion/SKILL.md) (1 hop)
5. **IF** the body can be sent as multipart or urlencoded interchangeably **THEN** mutate the container per the WAFFLED result and confirm the origin still parses the field the WAF skipped
6. **IF** the request uses chunked transfer or an unusual content-type **THEN** treat the transfer framing as the mutated container and test whether the WAF reassembles it
7. **IF** the same parameter can be duplicated across query, body, and multipart **THEN** test parameter pollution so the WAF inspects one copy and the origin uses another
8. **IF** the payload is blocked but the underlying flaw is confirmed to exist **THEN** keep the original vulnerability skill such as [`sql-injection`](../sql-injection/SKILL.md) as the target and use this skill only to reach it
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`waf-and-web-monitoring`](../../../blue-team/detection-and-monitoring/waf-and-web-monitoring/SKILL.md)
10. **IF** the payload is blocked in every container and the origin never parses it **THEN** STOP and classify as the control working, a verified non-finding for a bypass

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| The container discrepancy is actually a full request desync | [`http-request-smuggling`](../http-request-smuggling/SKILL.md) | The invariant is front-end and back-end message framing, not signature evasion |
| The mutation smuggles a traversal sequence past the filter | [`path-traversal-and-lfi-encoding-bypass`](../path-traversal-and-lfi-encoding-bypass/SKILL.md) | The underlying sink is path resolution, reached through encoding |
| The bypass relies on Unicode folding between WAF and origin | [`unicode-normalization-and-charset-confusion`](../unicode-normalization-and-charset-confusion/SKILL.md) | The disagreement is canonical form, not container framing |
| Target matches `waf-bypass-and-payload-obfuscation-encoding-layers` | [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `waf-bypass-and-payload-obfuscation-comment-and-whitespace` | [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](../waf-bypass-and-payload-obfuscation-comment-and-whitespace/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `waf-bypass-and-payload-obfuscation-parser-differentials` | [`waf-bypass-and-payload-obfuscation-parser-differentials`](../waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `waf-bypass-and-payload-obfuscation-rule-specific-evasion` | [`waf-bypass-and-payload-obfuscation-rule-specific-evasion`](../waf-bypass-and-payload-obfuscation-rule-specific-evasion/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fingerprint the WAF and confirm the underlying flaw exists.** Identify the vendor from block-page markers and response headers, and verify through a benign oracle that a real vulnerability sits behind the filter, because evading a filter in front of nothing proves nothing.
2. **Isolate the blocking token.** Bisect the payload until the exact substring the signature matches is known, so later mutations can be measured against a known trigger.
3. **Record a blocked-versus-passed baseline.** Capture the response for the plain payload (blocked) and for a wholly benign request (passed), establishing the two reference points for the differential.
4. **Mutate the container, not the payload, first.** Following the WAFFLED result, re-send the identical payload in a different envelope: switch urlencoded to multipart, craft an unusual multipart boundary, change the charset, or duplicate the parameter, and see whether the WAF stops inspecting it.
5. **Confirm the origin still parses the mutated container.** A mutation the WAF skips but the origin also skips is not a bypass; verify the origin reconstructs and acts on the payload using the vulnerability own oracle.
6. **Stop condition.** Halt when the identical payload is (a) blocked plain and passed-and-parsed when the container is mutated, (b) blocked in every container, or (c) only reachable by a destructive action against the origin. Case (a) is a confirmed bypass, (b) means the control holds, (c) is out of scope for this skill.
7. **State what counts as proof.** Proof is the same payload blocked in the plain container and executed by the origin in the mutated container, captured as the WAF verdict for each container plus the origin own confirmation that the payload ran. A 200 response the origin ignored is not a bypass.
8. **Close with the structural fix.** Make the WAF and origin parse the request identically: constrain accepted content-types, reject ambiguous or duplicated containers, normalize before inspection, and keep the signature as defense in depth behind a parameterized or allowlisted sink. Verify by replaying every container form against the aligned configuration.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A payload blocked as urlencoded but passed when resent as multipart form-data | Proves the WAFFLED container-interchange bypass where the WAF and origin disagree on body type |
| An unusual multipart boundary that the WAF fails to split | Proves the WAF multipart parser diverges from the origin on boundary handling |
| A duplicated parameter where the WAF reads one copy and the origin another | Proves HTTP parameter pollution at the inspection boundary on that stack |
| A charset or content-type the WAF does not model but the origin accepts | Proves the inspection gap is the container label, not the payload bytes |
| The identical signatured token reaching the origin unchanged | Proves the mutation moved the content past the filter rather than altering it |
| Vendor block-page markers on the plain request only | Proves the WAF vendor and that its signature fired before mutation |
| The vulnerability own oracle firing behind the WAF | Proves the bypass reached a real flaw, not an inert endpoint |

## Worked Contrast

**Vulnerable pattern:**

```python
# WAF-style middleware that only parses urlencoded bodies
def inspect(request):
    if request.content_type == "application/x-www-form-urlencoded":
        for value in parse_qs(request.body).values():
            if SIGNATURE.search(" ".join(value)):
                raise Blocked()
    # multipart and other containers are passed on without inspection
    return forward(request)
```

**Hardened pattern:**

```python
SUPPORTED = {"application/x-www-form-urlencoded", "multipart/form-data",
             "application/json"}

def inspect(request):
    if request.content_type not in SUPPORTED:
        raise Blocked()  # reject containers the inspector cannot parse
    for value in normalize_and_extract(request):
        if SIGNATURE.search(value):
            raise Blocked()
    return forward(request)
```

**Why this matters:** The defect inspects only urlencoded bodies while the origin also accepts multipart, so the same payload in a multipart envelope is forwarded uninspected. The fix refuses containers the inspector cannot parse and decodes every supported container the way the origin does, so there is no envelope the origin parses but the filter skipped.

## When It Is NOT This Issue

- **No flaw behind the filter:** evading the WAF on an endpoint with no underlying vulnerability proves only that a signature did not fire; there is nothing to exploit.
- **Mutation the origin also drops:** a container the WAF skips but the origin also fails to parse carries the payload nowhere.
- **200 without execution:** a passed request whose payload the origin ignored is not a bypass; require the vulnerability oracle.
- **Self-inflicted encoding break:** over-encoding that corrupts the payload so neither side parses it is not an evasion.
- **Rate-limit or IP block, not signature:** a 429 or IP ban is a different control; mutating the container will not change it.
- **Monitor-mode WAF:** a WAF in detection-only mode never blocked the plain payload, so there is no block to bypass.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `waf-bypass-and-payload-obfuscation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `waf-bypass-and-payload-obfuscation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: waf-bypass-and-payload-obfuscation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-693 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`waf-bypass-and-payload-obfuscation-encoding-layers`](../waf-bypass-and-payload-obfuscation-encoding-layers/SKILL.md) - Web and Application (leaf)
- [`waf-bypass-and-payload-obfuscation-comment-and-whitespace`](../waf-bypass-and-payload-obfuscation-comment-and-whitespace/SKILL.md) - Web and Application (leaf)
- [`waf-bypass-and-payload-obfuscation-parser-differentials`](../waf-bypass-and-payload-obfuscation-parser-differentials/SKILL.md) - Web and Application (leaf)
- [`sql-injection`](../sql-injection/SKILL.md) - Web and Application (flagship)
- [`cross-site-scripting`](../cross-site-scripting/SKILL.md) - Web and Application (flagship)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `waf-bypass-and-payload-obfuscation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 33 |
| Distinct dataset sources | 10 |
| Top sources | OffsecCyber (11), hackerone_disclosed_reports (9), bugbounty-hunter-v1 (4), bug-bounty-pentest-en (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
