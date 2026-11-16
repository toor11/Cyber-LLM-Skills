---
name: web-app-fuzzing-and-automation
description: "Automates web testing at scale: request templating, payload list management, response diffing, and rate-safe fuzzing with Burp, ffuf, Nuclei and custom scripts. Use when repeating a test across many endpoints or parameters."
family: web-and-application
tier: leaf
triggers: ["web fuzzing", "automate web testing", "nuclei templates", "request templating", "burp automation"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [sql-injection, cross-site-scripting, csrf, ssrf]
---

# Web App Fuzzing and Automation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)

## Mechanism and Preconditions

This skill industrialises verification: it templates one request, substitutes a payload or wordlist position, and diffs each response against a calibrated baseline so a single validation invariant can be checked across hundreds of endpoints or parameters without hand-sending each. It is not itself an exploit; the decision it tests is whether the application validates and rate-limits input consistently, and its signal is a response differential (status, length, timing, or a reflected marker) that separates an accepting endpoint from a rejecting one. The automation itself introduces risk the methodology must manage: without a stable oracle it produces false positives, and without rate control it can degrade the target. The value gained is coverage, the ability to find the one endpoint among many where an expected validation or authorisation control is absent. Proof is always a reproducible differential on a named endpoint, re-confirmed by hand, not a tool's heuristic verdict.

- **Precondition chain:** A repeatable request shape with an isolatable injection position exists, a stable baseline and oracle can be established for that position, and the target tolerates the request rate the campaign uses without the rate limiter masking the signal.
- **Readable differential:** A request filled with a benign control value versus the same request filled from the fuzzing position; a candidate finding is a response that diverges in status, length, or timing from the baseline, and it is real only when that divergence reproduces by hand and disappears once the endpoint validates the input.
- **Empirical grounding:** CWE-20 Improper Input Validation and CAPEC-116 frame the class, and OWASP WSTG content-discovery and input-testing methodology anchor the discipline. SOURCES.md has no fuzzing-automation-specific advisory, so this skill stays at the taxonomy and methodology level.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the campaign is really discovering unlinked paths and files rather than testing a known parameter **THEN** switch to [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) for directory and endpoint enumeration
2. **IF** candidate parameters are unknown and must be mined before fuzzing values **THEN** read [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md)
3. **IF** the response oracle is boolean or blind and needs timing or out-of-band confirmation **THEN** pivot to [`injection-detection-methodology-confirmation-discipline`](../injection-detection-methodology-confirmation-discipline/SKILL.md)
4. **IF** the templated payload is being blocked by a WAF before the app sees it **THEN** read [`waf-bypass-and-payload-obfuscation`](../waf-bypass-and-payload-obfuscation/SKILL.md) and keep probes inside authorised scope
5. **IF** the concurrency itself is the test, with two requests racing one check **THEN** route to [`race-conditions-and-concurrency`](../race-conditions-and-concurrency/SKILL.md)
6. **IF** a confirmed differential needs turning into a reusable Nuclei template **THEN** keep the signature endpoint-specific and version it alongside the engagement notes
7. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`web-application-incident-response`](../../../blue-team/incident-response/web-application-incident-response/SKILL.md)
8. **IF** no stable baseline or oracle can be established for the position **THEN** STOP and record a verified non-finding rather than reporting a tool heuristic

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Goal is unlinked paths, not parameter values | [`web-recon-and-content-discovery`](../web-recon-and-content-discovery/SKILL.md) | Different invariant: surface discovery versus input validation |
| Parameters themselves are unknown | [`injection-detection-methodology-parameter-mining`](../injection-detection-methodology-parameter-mining/SKILL.md) | Routes to parameter mining, a prerequisite not a value test |
| Signal is blind and needs an out-of-band oracle | [`injection-detection-methodology-confirmation-discipline`](../injection-detection-methodology-confirmation-discipline/SKILL.md) | Invariant is confirmation discipline, not throughput |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the request template and isolate one position.** Capture a known-good request, mark exactly one substitution point (a header, a path segment, a parameter value), and freeze everything else so each result is attributable to that single position.
2. **Build the oracle before the wordlist.** Decide in advance what distinguishes accept from reject for this position: status code, response-length band, a reflected marker, a timing threshold, or an out-of-band callback. A campaign without a declared oracle cannot be triaged.
3. **Calibrate a baseline and auto-filter the noise.** Send several benign controls to learn the normal status and length distribution, then configure auto-calibration so generic catch-all responses are filtered out before real hits surface.
4. **Set rate and concurrency to a safe envelope.** Choose request spacing and parallelism that stay under the target's rate limit and resource budget, and record it, so a 429 wave neither corrupts the differential nor harms the service.
5. **Run the campaign and diff every response against the baseline.** Collect status, length, word count, and timing per request and flag only those outside the calibrated band as candidates.
6. **Stop condition.** Halt a given position when it either (a) yields a candidate differential that reproduces on a single hand-sent request, (b) produces nothing outside the baseline band across the full list, or (c) begins returning rate-limit or error pages that make results unreliable. Outcome (a) is a candidate to escalate, (b) is a non-finding, (c) means pause and re-pace, not conclude.
7. **State what counts as proof.** Proof is a hand-reproduced response differential on a named endpoint and position, with the benign control and the triggering input shown side by side, not a scanner's confidence score. The finding's class is then handed to the matching technique skill for exploitation-free confirmation.
8. **Close with the structural fix and verify it.** The target-side fix is consistent server-side validation (schema or allowlist) on the identified position plus a rate limit that does not leak a distinguishing oracle; re-run the same template to confirm the differential is gone and the baseline is uniform.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A response-length or word-count band that separates valid from invalid inputs | Proves an enumeration oracle exists on the endpoint, usable by any list-driven fuzzer |
| A 200 catch-all that auto-calibration must filter before real hits appear | Proves the endpoint returns soft-404s, so uncalibrated results are false positives |
| A timing threshold that only a subset of payloads crosses | Proves a blind differential that needs repeated sampling to clear jitter |
| A reflected unique marker echoed only for accepted inputs | Proves a reliable in-band oracle for that position on that stack |
| A 429 or Retry-After appearing mid-campaign | Proves a rate limiter is active and the campaign envelope must be reduced |
| One endpoint among many diverging from the family baseline | Proves inconsistent validation across sibling routes, the usual payoff of scale testing |
| Identical responses to valid and invalid inputs after a fix | Proves the oracle was closed, the verification that remediation worked |

## Worked Contrast

**Vulnerable pattern:**

```python
@app.route('/api/coupon/<code>')
def check_coupon(code):
    coupon = db.find_coupon(code)      # no validation, no rate limit
    if coupon is None:
        return jsonify(error='unknown coupon'), 404   # distinct length + status
    return jsonify(valid=True, discount=coupon.discount), 200
```

**Hardened pattern:**

```python
@app.route('/api/coupon/<code>')
@rate_limit(key='ip', limit='10/min')          # bounds automated enumeration
def check_coupon(code):
    if not re.fullmatch(r'[A-Z0-9]{8,16}', code):
        return UNIFORM_RESPONSE                  # reject invalid shape uniformly
    db.queue_for_review(code)
    # Same status and body shape whether or not the code exists
    return UNIFORM_RESPONSE
```

**Why this matters:** The defect is a distinguishing response plus no rate limit, which together turn the endpoint into a free enumeration oracle that automation walks end to end. The fix validates the code shape, caps the request rate per client, and returns one uniform response regardless of existence, so a list-driven campaign learns nothing from the differential.

## When It Is NOT This Issue

- **Scanner confidence without reproduction:** a tool flagging a hit that does not reproduce on a single hand-sent request is a heuristic artefact, not a finding.
- **Soft-404 catch-all:** divergence from a hardcoded path baseline that is actually a generic 200 page is a calibration failure, not an exposed endpoint.
- **Rate-limit page as signal:** treating 429 or a WAF challenge as a distinguishing response conflates defence with an oracle.
- **Baseline drift:** length changes caused by dynamic content such as timestamps, CSRF tokens, or adverts rather than the fuzzed input are noise, not differentials.
- **Self-scoped test data:** enumerating only objects the tester owns proves throughput, not a cross-user exposure.
- **Cached responses:** identical responses served from a cache rather than the origin can hide a real differential or invent a false one.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `web-app-fuzzing-and-automation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `web-app-fuzzing-and-automation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: web-app-fuzzing-and-automation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-20 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `web-app-fuzzing-and-automation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 30 |
| Distinct dataset sources | 8 |
| Top sources | OffsecCyber (17), bugbounty-hunter-v1 (4), CYBER_CPT/gh_advisories (3), hackerone_disclosed_reports (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 1 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
