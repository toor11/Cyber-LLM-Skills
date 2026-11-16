---
name: ssrf-blind-ssrf
description: Blind SSRF confirmation and exfiltration. Covers confirming SSRF without a response body using OAST callbacks, timing, error differentials and side channels, then extracting data through DNS or response-length oracles. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: web-and-application
tier: leaf
triggers: ["blind ssrf", "ssrf oob", "ssrf exfiltration", "ssrf timing"]
cwe: [CWE-918]
owasp: [A10:2021]
attack: [T1190]
capec: [CAPEC-664]
related: [ssrf, ssrf-cloud-metadata, ssrf-internal-service-pivot, ssrf-protocol-smuggling]
parent: ssrf
---

# SSRF Blind SSRF - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Web and Application`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Blind SSRF gives no response body, status, or error to read, so confirmation rests on side channels: an out-of-band callback, a timing differential, or a distinguishable error between open and closed internal ports. The security question is the same as in-band SSRF, but the oracle changes, and the discipline is correlation. A callback is only proof when it originates from the target own egress address, arrives at the time the single request was issued, and maps to that one request through a unique token. A bare DNS resolution proves a resolver was asked, not that the server connected, so confirmation requires the HTTP or TCP stage rather than just the lookup. Timing is usable only after a noise baseline is measured, because jitter on a busy backend will otherwise masquerade as a conditional delay.

- **Precondition chain:** A request-controlled destination reaches a server-side fetch that returns nothing readable, a side channel exists such as an OAST callback, measurable timing, or an error differential, and each probe can be correlated to one request through a unique token or controlled address.
- **Readable differential:** A request to a unique assessor-controlled token versus a control request; a finding exists when a callback arrives from the target egress at the expected moment and correlates with that one token, and no callback or timing shift appears for the control.
- **Empirical grounding:** CWE-918 under OWASP Top 10:2025 A01:2025 Broken Access Control; SOURCES.md carries no blind-SSRF-specific out-of-band advisory, so this stays at taxonomy level and leans on OAST correlation discipline.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the profile is not yet confirmed to be a blind fetch **THEN** start at the parent class [`ssrf`](../ssrf/SKILL.md) first (1 hop)
2. **IF** a response body or status is actually reflected **THEN** return to [`ssrf`](../ssrf/SKILL.md) and use the in-band oracle instead
3. **IF** a unique OAST token is available **THEN** correlate the callback to one request before claiming confirmation
4. **IF** only timing is observable **THEN** measure the jitter baseline across repeated control requests before any conditional probe
5. **IF** the callback is DNS only with no HTTP stage **THEN** treat it as resolution, not connection, and seek the HTTP or TCP stage
6. **IF** the target is link-local metadata behind the blind fetch **THEN** switch to [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) (1 hop)
7. **IF** the blind fetch reaches an internal service **THEN** switch to [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) (1 hop)
8. **IF** the OAST methodology itself is the focus **THEN** read [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md)
9. **IF** the user asks how to detect, hunt, or remediate this behavior **THEN** pivot to the paired Blue skill [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
10. **IF** no side channel survives after inspection **THEN** STOP and classify as a verified non-finding rather than forcing a guess

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Callback is DNS only, no HTTP | [`oast-and-blind-vulnerability-testing`](../oast-and-blind-vulnerability-testing/SKILL.md) | Resolution alone is not connection; the oracle discipline differs |
| Blind fetch reaches an internal TCP service | [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) | Impact is protocol interaction, a different invariant |
| Blind fetch reaches metadata | [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) | Impact is credential exposure through the instance role |
| Need parent class methodology | [`ssrf`](../ssrf/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Confirm the fetch is genuinely blind.** Verify no body, status, redirect target, or error text varies with the destination; if any does, this is in-band SSRF and belongs to the parent skill.
2. **Choose a correlated oracle.** Allocate a unique OAST subdomain per request so a callback maps to exactly one probe, or select a timing or port-error channel if no egress is permitted. Correlation, not mere arrival, is the design goal.
3. **Measure the noise baseline first.** For timing, send the control request many times and record the latency distribution; for callbacks, confirm the OAST endpoint is quiet without a probe. This baseline precedes any conditional probe so jitter is not read as signal.
4. **Issue one probe against the unique token.** Point the parameter at the per-request OAST host and watch for a callback that arrives at the issue time and originates from the target egress address, not a shared resolver or a third party.
5. **Attribute the callback to the server, not a resolver.** Require the HTTP or TCP stage of the interaction and the server own source address; a DNS-only hit is logged as resolution and does not confirm the fetch.
6. **Stop condition.** Halt when a probe produces a correlated callback from the target egress at the expected time, or produces no callback and no timing shift beyond the baseline, or would require pulling real internal content to advance. The first confirms, the second is a non-finding, the third is out of scope.
7. **State what counts as proof.** Proof is a callback tied to one unique token, originating from the target infrastructure at the moment the request was issued, or a timing delta that exceeds the measured jitter baseline and tracks a conditional. A resolver query with no connection, or a timing blip inside the baseline, is not proof.
8. **Close with the structural fix.** Remove the attacker control of the destination or resolve-and-pin to a public allowlist, disable redirects, and block egress from the fetch tier so even a reachable primitive cannot call out. Verify by replaying the unique-token probe and confirming no correlated callback against the patched build.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| A callback arriving from the target egress IP at the request time | Proves the server issued the fetch on a blind path, the core confirmation for this class |
| A unique per-request OAST token matching exactly one probe | Proves correlation to a single request rather than ambient noise, on any stack with an outbound path |
| A DNS-only hit with no subsequent HTTP connection | Proves resolution occurred but not connection, so by itself it is not confirmation |
| A timing delta that exceeds the measured jitter baseline and tracks a conditional | Proves a time-based blind oracle where no egress callback is allowed |
| Distinct errors or timings for a closed versus open internal port | Proves port-level reachability as a low-noise oracle without reading data |
| A callback from a shared resolver rather than the target egress | Proves only that a resolver was queried, a common false positive to exclude |
| Repeated probes correlating one-to-one with repeated callbacks | Proves the channel is deterministic, separating signal from background interaction |

## Worked Contrast

**Vulnerable pattern:**

```python
import requests

def ping_url(url: str) -> None:
    # Fire-and-forget fetch: no response is returned and the destination is caller-controlled
    try:
        requests.get(url, timeout=3)
    except requests.RequestException:
        pass  # errors are swallowed, so the path is blind by design
```

**Hardened pattern:**

```python
import ipaddress
import socket
import urllib.parse
import requests

ALLOWED = {"hooks.example"}

def ping_url(url: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED:
        raise ValueError("destination not allowed")
    addr = socket.getaddrinfo(parts.hostname, 443, proto=socket.IPPROTO_TCP)[0][4][0]
    if not ipaddress.ip_address(addr).is_global:
        raise ValueError("resolves to a non-public address")
    requests.get(url, timeout=3, allow_redirects=False)
```

**Why this matters:** The defect swallows all errors and lets any destination through, which is exactly the blind primitive an OAST probe confirms. The fix constrains the destination to an exact allowlist, resolves and checks for a globally routable address, forbids redirects, and relies on an egress firewall so a blind call cannot reach internal infrastructure.

## When It Is NOT This Issue

- **DNS-only callback:** a resolver lookup with no HTTP or TCP stage proves resolution, not that the server connected.
- **Third-party or shared resolver hit:** a callback from a public resolver address, not the target egress, does not attribute the fetch to the target.
- **Timing inside the baseline:** a latency blip within the measured jitter range is noise, not a conditional delay.
- **Uncorrelated callback:** a hit that cannot be tied to one unique token may come from scanners or caching, not your probe.
- **Egress blocked:** a reachable primitive whose tier cannot call out produces no callback and is a code defect at reduced severity.
- **Client-side fetch:** a URL requested by the victim browser is client-side forgery, not a server blind fetch.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ssrf-blind-ssrf` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ssrf-blind-ssrf` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ssrf-blind-ssrf
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-918 | Mapping: T1190]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`ssrf`](../ssrf/SKILL.md) - Web and Application (flagship)
- [`ssrf-cloud-metadata`](../ssrf-cloud-metadata/SKILL.md) - Web and Application (leaf)
- [`ssrf-internal-service-pivot`](../ssrf-internal-service-pivot/SKILL.md) - Web and Application (leaf)
- [`ssrf-protocol-smuggling`](../ssrf-protocol-smuggling/SKILL.md) - Web and Application (leaf)
- [`ssrf-allowlist-bypass`](../ssrf-allowlist-bypass/SKILL.md) - Web and Application (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ssrf-blind-ssrf` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-918, T1190`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 37 |
| Distinct dataset sources | 6 |
| Top sources | OffsecCyber (17), hackerone_disclosed_reports (8), CYBER_CPT/nuclei_templates (5), bugbounty-hunter-v1 (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 5 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
