---
name: osint-methodology
description: "Runs structured OSINT: requirement definition, source selection, collection logging, verification and bias control. Use at the start of any investigation requiring external information."
family: osint-and-red-operations
tier: core
triggers: ["osint methodology", "open source intelligence", "osint process", "collection plan"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology-collection-and-logging, osint-methodology-verification-and-bias, corporate-and-person-osint, infrastructure-osint]
---


# OSINT Methodology - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

The governing discipline for an OSINT engagement: turn a question into a collection plan with named sources, define what would count as an answer, collect with logged provenance, and then verify before reporting. Everything else in this family is a source or a technique; this skill is the loop that keeps them from producing confident nonsense.

- **A plan names falsifiers.** For each question, write the observation that would refute the leading hypothesis; a plan without falsifiers produces confirmation, not intelligence.
- **Provenance is collected, not reconstructed.** Source, retrieval time, and a hash of the raw record are stored at collection; a report assembled from memory cannot be defended.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target resolves to `osint-methodology-collection-and-logging` **THEN** switch to [`osint-methodology-collection-and-logging`](../osint-methodology-collection-and-logging/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
2. **IF** the target resolves to `osint-methodology-verification-and-bias` **THEN** switch to [`osint-methodology-verification-and-bias`](../osint-methodology-verification-and-bias/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
3. **IF** the question cannot be expressed as a checkable proposition **THEN** rewrite it before collecting, because no source resolves an unanswerable question.
4. **IF** two sources disagree **THEN** record both observations with their timestamps and treat the disagreement as the finding rather than picking the convenient one.
5. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
6. **IF** the input cannot establish the precondition this skill needs — a written question, an authorised scope, and at least one falsifier per hypothesis — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `osint-methodology-collection-and-logging` | [`osint-methodology-collection-and-logging`](../osint-methodology-collection-and-logging/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `osint-methodology-verification-and-bias` | [`osint-methodology-verification-and-bias`](../osint-methodology-verification-and-bias/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A collection plan document plus a provenance store (SQLite or CSV) with `source`, `fetched_at`, `raw_sha256` per observation
- **First Check:** `sqlite3 osint.db "SELECT source, COUNT(*) FROM obs GROUP BY source;"`

1. Confirm the target surface: restate the request as one or more checkable propositions, and for each name the source class that could answer it (registry, certificate, archive, human).
2. Choose the branch: identity resolution when the question is who, infrastructure attribution when it is what, and temporal analysis when it is when or whether something changed.
3. Define the differential: state the observation that would confirm and the observation that would refute, then collect for both; a plan that only seeks confirmation is not a plan.
4. Name the stop condition: a source budget and a saturation rule (no new entities from two consecutive sources), so collection ends on evidence rather than on exhaustion.
5. Prove it: every claim in the report resolves to stored observations with timestamps, and every inference names the observations it rests on.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Checkable proposition with an explicit falsifier` | Turns a vague request into something a source can settle, which is the precondition for every later step. |
| `Source class per question` | Registry, certificate transparency, archive, and human sources answer different questions; naming the class prevents using a weak source for a strong claim. |
| `Saturation rule across sources` | Ends collection when new sources stop adding entities, which is the defensible stopping criterion rather than a page limit. |
| `Observation table keyed by hash and timestamp` | Makes every later inference traceable and every retraction possible. |

## Worked Contrast

**Collection Without a Plan or a Falsifier:**

```text
Question: is target.example run by the same operator as other.example?
Collection: search both names, read the first three results each, write a paragraph.
# BUG: no source recorded, no falsifier, no timestamp, no way to check the conclusion later
```

**Plan With Falsifiers and a Provenance Store:**

```text
Question: does the operator of target.example control other.example?
Confirm if: shared registrant organisation OR shared authoritative NS pair issued before 2025.
Refute if: both domains use distinct registrars AND distinct NS pairs AND distinct certificate issuers.
Sources: RDAP for both, CT logs for both, archive snapshots for the NS change history.
Store: source, fetched_at, raw_sha256 per response.
```

**Why this matters:** The first version records an impression, and when a stakeholder challenges it there is nothing to re-examine. Writing the refuting observation in advance forces collection to look for disconfirming evidence, and storing provenance means the conclusion can be re-derived or withdrawn when a source changes.

## When It Is NOT This Issue

- **Aggregator output treated as a primary source.** Aggregators infer and merge; confirm the field in the registry or certificate itself.
- **Single-source agreement read as corroboration.** Two sites quoting the same press release are one source.
- **Stale archive read as current state.** An archived page describes the retrieval date, not today.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `osint-methodology` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `osint-methodology` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: osint-methodology
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology-collection-and-logging`](../osint-methodology-collection-and-logging/SKILL.md) - OSINT and Red Operations (leaf)
- [`osint-methodology-verification-and-bias`](../osint-methodology-verification-and-bias/SKILL.md) - OSINT and Red Operations (leaf)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `osint-methodology` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 33 |
| Distinct dataset sources | 9 |
| Top sources | osint-tool-database (16), CYBER_CPT/L5/ctf_search (7), bugbounty-hunter-v1 (3), CYBER_CPT/github_security_md (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 16 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
