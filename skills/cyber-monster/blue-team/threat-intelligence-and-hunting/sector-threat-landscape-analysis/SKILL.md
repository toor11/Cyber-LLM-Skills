---
name: sector-threat-landscape-analysis
description: "Analyzes the threat landscape for a sector: prevalent actors, common initial access, industry targeting and benchmark comparison. Use when setting strategy or briefing leadership."
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["threat landscape", "sector threat", "industry targeting"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management, threat-hunting]
---

# Sector Threat Landscape Analysis - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

A sector landscape describes what is actually happening to organisations like yours, with the sampling bias made explicit. The inputs are incident disclosure, ISAC reporting, vendor telemetry, and your own observations, and each has a different bias: disclosed incidents over-represent organisations with retainers, vendor telemetry over-represents the vendor's customer base, and your own data is precise but narrow. The product is a set of statements about prevalence and targeting with those biases attached.

- **CWE-200 framing:** sector products aggregate victim detail from multiple sources; aggregation is a disclosure risk when the cohort is small.
- Prevalence claims need a denominator: the number of organisations in the sector, not the number of reports received.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the consumer needs to make an investment decision **THEN** open `threat-intelligence-and-cti-strategic-intelligence` for the decision framing.
2. **IF** the input is a specific actor campaign **THEN** open `threat-intelligence-and-cti-tactical-intelligence` for the observables.
3. **IF** the question is your own external exposure **THEN** open `osint-for-defenders`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Define the cohort precisely.** Sub-sector, size band, geography, and technology profile. A landscape for 'healthcare' covers organisations with nothing in common; the narrower cohort makes prevalence meaningful.
2. **Classify each input by its bias.** Disclosed incidents, ISAC reporting, vendor telemetry, regulator notification, and your own observations. Record which bias each carries before combining them.
3. **Choose the branch on the claim type.** Prevalence takes the denominator branch; targeting takes the victimology branch; technique shift takes the observable-trend branch.
4. **Define the baseline-vs-probe differential.** Baseline: last year's landscape for the same cohort. Probe: this period. A change claim needs both under the same method, otherwise the shift may be a reporting change.
5. **State the stop condition and the proof.** Stop when every claim has a denominator, a source class, and a bias note; proof is the cohort definition plus the denominators behind the headline numbers.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Prevalence claim with the cohort denominator stated | Proves the number means something; '35% of attacks' without a denominator is a reporting artefact. |
| Technique shift traced to a change in reporting rather than actor behaviour | Proves the trend is real or that the product is measuring its own sources. |
| Small-cohort victim detail aggregated | Proves a disclosure risk; with five victims, naming any detail can identify one. |
| Regulator notification data used as a prevalence input | Proves a bias: notification thresholds vary by jurisdiction and sector, so counts are not comparable. |

## Worked Contrast

**Landscape built from headline counts:**

```text
Sector Threat Update - Manufacturing
- Ransomware attacks up 40% this year
- 62% of attacks began with phishing
- Supply chain is the top concern
Sources: vendor blogs, news coverage
Recommendation: strengthen email defences
```

**Landscape with cohort, denominators, and bias notes per claim:**

```text
Cohort: mid-market discrete manufacturing, 200-2,000 staff, EU, ERP-heavy (n=1,840 orgs)

Claim 1 - initial access
  38% of observed intrusions in this cohort began with edge-appliance exploitation, up from 12%.
  Sources: ISAC member reports (n=41), vendor IR retainer data (n=19), regulator notifications (n=8).
  Bias: ISAC members are more mature and more likely to detect appliance exploitation; retainer clients
        over-represent organisations that can afford IR. True prevalence is uncertain in both directions.
  Confidence: moderate.

Claim 2 - extortion behaviour
  Median time from access to extortion demand fell from 9 days to 4 days (n=27 with timestamps).
  Bias: timestamps come only from organisations that retained IR support.
  Confidence: moderate; direction is consistent across two independent sources.

Claim 3 - regulator notifications
  Counts rose 30%, but the reporting threshold changed in two jurisdictions during the period.
  Conclusion: not evidence of increased incidence. Excluded from the prevalence claim.

What this changes: email hardening remains relevant but ranks below appliance patching for this cohort.
```

**Why this matters:** The first product reports percentages with no cohort, no denominators, and no bias, so the 40% figure cannot be interpreted and the recommendation follows from the vendor blog rather than from the data. The second defines the cohort and its size, attaches source classes and their biases to each claim, explicitly excludes a claim that is a reporting artefact, and states what the analysis changes about priorities.

## When It Is NOT This Issue

- **Year-over-year increase explained by a reporting threshold change.** That is a measurement artefact; excluding it from prevalence is correct, not a gap.
- **Vendor telemetry over-representing one sector.** State the bias and use it for technique detail rather than prevalence.
- **Small cohort with named victim details.** Aggregation does not anonymise when the cohort is five organisations.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `sector actor` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `sector-threat-landscape-analysis` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: sector-threat-landscape-analysis
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`hypothesis-driven-hunting`](../hypothesis-driven-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `sector-threat-landscape-analysis` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 8 |
| Top sources | cyber-security/CyberSec-Dataset (6), CYBER_CPT/h4cker (2), SecEval/attck (1), CYBER_CPT/unit42 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
