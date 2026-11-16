---
name: osint-methodology-verification-and-bias
description: OSINT verification and bias control. Covers triangulating sources, identifying fabrication and avoiding confirmation bias in intelligence assessment. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: osint-and-red-operations
tier: leaf
triggers: ["osint verification", "source credibility", "intelligence bias"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, osint-methodology-collection-and-logging, corporate-and-person-osint, infrastructure-osint]
parent: osint-methodology
corpus_sparse: true
---


# OSINT Methodology Verification and Bias - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Verification is the step that converts an observation into a claim: corroborate across independent sources, check whether the sources share an origin, and actively look for the observation that would break the leading hypothesis. The failure mode is not a lack of sources but an excess of dependent ones, which reads as agreement.

- **Independence is a property of origin, not of domain.** Ten sites syndicating one press release are one source; a registry record and a certificate are two.
- **Bias shows up as source selection.** If every source in the plan can only confirm the hypothesis, the conclusion was decided before collection.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** two sources agree **THEN** check whether one quotes the other before counting them as corroboration.
2. **IF** the leading hypothesis is comfortable **THEN** deliberately collect against it and record what the attempt found.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — at least two independent sources per claim, and a recorded attempt to refute the leading hypothesis — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`osint-methodology`](../osint-methodology/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A corroboration table mapping claim to sources with an independence flag, plus a refutation attempt recorded per claim
- **First Check:** `sqlite3 osint.db "SELECT claim, COUNT(DISTINCT origin) FROM corroboration GROUP BY claim;"`

1. Confirm the target surface: list the claims in the draft and the sources behind each, and mark which sources share an origin.
2. Choose the branch: document verification for paper records, technical verification for infrastructure (certificates, DNS, routing), and human verification for interviews.
3. Define the differential: for each claim, state the observation that would falsify it and collect that observation; the differential is whether the falsifier was found.
4. Name the stop condition: two independent origins per claim, or an explicit statement that only one origin exists and the claim is therefore single-sourced.
5. Prove it: the report marks each claim with its source count and independence, and names the refutation attempt that was made.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Independence flag per source origin` | Prevents syndicated copies from counting as corroboration, the most common verification error. |
| `Falsifier recorded per claim` | Forces the analysis to look for disconfirming evidence rather than accumulating support. |
| `Origin identifier (publisher, registry, certificate)` | Groups sources that share an origin so the count reflects independence. |
| `Single-sourced flag in the report` | Makes the evidentiary strength visible instead of implied. |

## Worked Contrast

**Corroboration by Counting Search Results:**

```text
Claim: the company operates the datacenter.
Sources: news-site-a, news-site-b, news-site-c all state it.
# BUG: all three quote the same press release, so this is one source counted three times
```

**Corroboration by Independent Origin With a Refutation Attempt:**

```text
Claim: the company operates the datacenter.
Origin 1: company press release (primary, self-interested).
Origin 2: regional peering registry entry listing the company's ASN at that facility.
Origin 3: certificate transparency record issued to the company for a host in that facility's address range.
Refutation attempted: checked the facility operator's own tenant list; company absent there (conflict noted).
Verdict: two independent origins support operational presence; tenant-list absence recorded as a conflict, not suppressed.
```

**Why this matters:** Three sites quoting one release is a single origin with three copies, and counting them inflates confidence without adding evidence. Grouping by origin and recording the conflicting tenant list produces a claim that states its own strength and the evidence against it, which is what survives review.

## When It Is NOT This Issue

- **Syndicated copies counted as independent.** Check the byline and the quoted source before incrementing the count.
- **Self-interested source treated as neutral.** A company's own release about its operations is primary but interested; label it.
- **Absence of a record read as absence of the fact.** A tenant list that omits a name may be incomplete; record the conflict rather than the conclusion.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `osint-methodology-verification-and-bias` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `osint-methodology-verification-and-bias` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: osint-methodology-verification-and-bias
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`osint-methodology-collection-and-logging`](../osint-methodology-collection-and-logging/SKILL.md) - OSINT and Red Operations (leaf)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `osint-methodology-verification-and-bias` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
