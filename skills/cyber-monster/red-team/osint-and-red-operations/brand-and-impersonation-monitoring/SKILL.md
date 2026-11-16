---
name: brand-and-impersonation-monitoring
description: "Detects brand abuse and impersonation: typosquatted domains, lookalike social accounts, phishing infrastructure and counterfeit app listings. Use in defensive OSINT or pre-engagement reconnaissance."
family: osint-and-red-operations
tier: leaf
triggers: ["brand monitoring", "typosquat domain", "lookalike account", "phishing infrastructure"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-163]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Brand and Impersonation Monitoring - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Detecting infrastructure that imitates a brand: lookalike domain registrations, certificate transparency entries for those names, and content similarity to the legitimate site. The programme is continuous, so the engineering problem is a low-noise alert — a watchlist of patterns plus a differential against the genuine site, rather than a keyword feed.

- **Registration patterns beat brand strings.** Homoglyph, transposition, and added-word patterns generate candidates; the certificate and content checks then decide which are impersonation.
- **The genuine site is the baseline.** A candidate is an impersonation when it serves brand content while differing in the fields that matter (login form action, contact details, certificate subject).

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the candidate has no certificate and no content **THEN** record it as a defensively registered lookalike and deprioritise it.
2. **IF** the candidate serves a login form **THEN** compare the form action host and the certificate subject against the genuine site before alerting.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a brand pattern watchlist, the genuine site as baseline, and a certificate transparency interface — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** Pattern generation over the brand name, CT lookups for candidates, and content comparison against the genuine site — each candidate stored with the check that flagged it
- **First Check:** `curl -sS 'https://crt.sh/?q=%25target%25&output=json' | jq -r '.[].name_value'`

1. Confirm the target surface: define the brand strings, the legitimate domains, and the fields that distinguish genuine content (login action, contact details, certificate subject).
2. Choose the branch: registration monitoring for new domains, certificate monitoring for names issued certificates, and content monitoring for active impersonation.
3. Define the differential: fetch the candidate and the genuine site, and compare the three distinguishing fields; a candidate matching on none is noise, one matching content and differing on the login action is a phishing site.
4. Name the stop condition: a candidate cap per run and a review queue ordered by the number of matching fields.
5. Prove it: each alert carries the candidate URL, the certificate subject, the matched content fields, and a screenshot hash, so a reviewer can confirm without revisiting the site.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Homoglyph and transposition patterns` | Generates candidates systematically; the register of generated patterns is what makes coverage measurable. |
| `Certificate subject and issuer for a candidate` | Shows whether the name is served over TLS and by which issuance path, which separates live from parked domains. |
| `Login form action host` | The field that most reliably distinguishes a phishing page from a parked lookalike. |
| `Screenshot hash of the candidate` | Evidence that survives the site being taken down, and a fast way to spot template reuse across candidates. |

## Worked Contrast

**Keyword Feed of Brand Mentions:**

```text
Alert on any newly registered domain containing 'target'.
Queue fills with parked domains, fan sites, and unrelated trademarks.
# BUG: no content check, no distinction between parked and active impersonation
```

**Pattern Watchlist With Content Differential:**

```text
Candidate: target-secure-login.example (matched pattern: added-word 'secure' + 'login').
Certificate: issued by a public CA 2026-10-28, subject CN=target-secure-login.example.
Content: served page hash matches the genuine login page template (hash 9f2c...).
Login form action: posts to collect.example, not to the genuine host -> impersonation.
Screenshot hash recorded for evidence.
```

**Why this matters:** A keyword alert on registrations produces a queue dominated by parked domains and unrelated businesses, so analysts stop reading it. Requiring a content match against the genuine site and then comparing the form action identifies active impersonation, and the screenshot hash preserves evidence after takedown.

## When It Is NOT This Issue

- **Parked lookalike with no content.** A defensively registered or speculative domain is not an active impersonation.
- **Fan site or review site using the brand name.** Legitimate use of a trademark is not impersonation; check the content and the login behaviour.
- **Certificate issued to a name that never resolves.** Certificate transparency records names before they are served; resolution is a separate observation.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `brand-and-impersonation-monitoring` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `brand-and-impersonation-monitoring` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: brand-and-impersonation-monitoring
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `brand-and-impersonation-monitoring` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 23 |
| Distinct dataset sources | 8 |
| Top sources | osint-tool-database (16), cyber-security/CyberSec-Dataset (1), CYBER_CPT/L5/ctf_search (1), CYBER_CPT/blackhills (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
