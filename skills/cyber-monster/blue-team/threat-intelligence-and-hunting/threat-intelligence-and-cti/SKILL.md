---
name: threat-intelligence-and-cti
description: "Runs cyber threat intelligence: requirements definition, collection planning, analysis and dissemination at strategic, operational and tactical levels. Use when producing or consuming threat intelligence."
family: threat-intelligence-and-hunting
tier: core
triggers: ["threat intelligence", "cti", "cyber threat intel", "intelligence cycle"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti-tactical-intelligence, threat-intelligence-and-cti-strategic-intelligence, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management]
---

# Threat Intelligence and CTI - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Cyber threat intelligence exists to change a decision, so every product is judged by the decision it informed: a detection written, a control changed, an exposure closed, or a risk accepted with a record. The discipline is therefore requirements-first - a named consumer, a decision they face, and the intelligence that would change it - rather than collection-first. The output that survives is the one with an estimative statement, its confidence, and the evidence behind it, because a claim without those three cannot be acted on defensibly.

- **CWE-200 framing:** most intelligence failures are disclosure or integrity problems - a claim that cannot be traced to evidence, or an indicator treated as a conclusion.
- ATT&CK v19 (April 2026) split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112), so any mapping produced before that release needs re-checking against the crosswalk rather than assumed.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is what an actor does rather than what to do about it **THEN** open `threat-intelligence-and-cti-tactical-intelligence` for TTP-level output.
2. **IF** the consumer is an executive or a risk register **THEN** open `threat-intelligence-and-cti-strategic-intelligence`.
3. **IF** the request is a hunt rather than a product **THEN** open `threat-hunting` and use the intelligence as a hypothesis source.
4. **IF** the claim rests on a single vendor report **THEN** record it as moderate confidence with one source rather than raising it to an assessment.
5. **IF** the target narrows to `threat-intelligence-and-cti-tactical-intelligence` **THEN** open [`threat-intelligence-and-cti-tactical-intelligence`](../threat-intelligence-and-cti-tactical-intelligence/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.
6. **IF** the target narrows to `threat-intelligence-and-cti-strategic-intelligence` **THEN** open [`threat-intelligence-and-cti-strategic-intelligence`](../threat-intelligence-and-cti-strategic-intelligence/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `threat-intelligence-and-cti-tactical-intelligence` | [`threat-intelligence-and-cti-tactical-intelligence`](../threat-intelligence-and-cti-tactical-intelligence/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `threat-intelligence-and-cti-strategic-intelligence` | [`threat-intelligence-and-cti-strategic-intelligence`](../threat-intelligence-and-cti-strategic-intelligence/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Write the requirement with its consumer and decision.** 'Which ransomware families are using edge-appliance initial access against our sector, so we can prioritise patching' beats 'ransomware landscape'. Record who acts and when the decision expires.
2. **Separate observation from assessment.** An observation is what a source reported; an assessment is your judgement with a confidence level. Keep them in different fields so a reader can see where the evidence stops.
3. **Choose the branch on the decision type.** Detection decisions take the TTP branch; exposure decisions take the infrastructure and sector branch; risk decisions take the likelihood-and-impact branch.
4. **Define the baseline-vs-probe differential for the product.** Baseline: the decision as it stands today. Probe: what the consumer would do differently if the assessment is right. If nothing changes, the product has no customer and should be a monitoring note instead.
5. **State the stop condition and the proof.** Stop when the product carries an estimative statement, its confidence, the evidence with dates, and a named consumer action; proof is the decision record that cites the product.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Requirement naming a consumer, a decision, and an expiry | Proves the product has a customer; without this, collection expands to fill available time. |
| Confidence level tied to source count and corroboration | Proves the assessment is calibrated rather than asserted; a single-source claim cannot be high confidence. |
| ATT&CK mapping using the v19 tactic split | Proves the mapping is current; a Defense Evasion label after April 2026 indicates an unrefreshed library. |
| Diamond Model vertices populated for an incident | Proves the analysis has adversary, capability, infrastructure, and victim linked rather than only indicators. |

## Worked Contrast

**Collection-driven product with no consumer or decision:**

```text
Weekly Threat Intel Bulletin
- Ransomware remains a top threat.
- New malware family observed in the wild.
- 412 new IOCs added to the blocklist.
- Recommendation: remain vigilant and patch systems.
Sources: vendor blogs, Twitter/X, news
```

**Requirement-driven product with an estimative statement and a decision:**

```text
PIR-2026-14  Consumer: edge-platform team  Decision: Q1 patch order  Expires: 2027-01-15
Assessment (moderate confidence)
  Two ransomware affiliates tracked since 2026-08 have moved initial access to internet-facing
  VPN appliances in our sector, favouring appliances without MFA on the management plane.

Evidence
  2026-09-12  vendor A: 3 intrusions, appliance model X, no MFA   (primary reporting)
  2026-10-03  vendor B: same affiliate cluster, same model        (corroborates)
  2026-10-28  our telemetry: 41 appliances, 9 without MFA         (internal exposure)

What changes if true
  Patch order moves those 9 appliances ahead of the scheduled web-tier work.
  Detection: add auth-success-after-failed-MFA burst on appliance logs.

Confidence rationale: two independent vendors plus internal exposure data; no primary artefact seen.
Dissemination: edge-platform sync 2026-11-04 (decision recorded, owner acknowledged).
```

**Why this matters:** The first product reports activity and recommends vigilance, so no decision moves and the IOC count is the only measurable output. The second names a consumer and a decision with an expiry, separates the judgement from the evidence, states what would change if it is right, and records the dissemination event - which is what makes the product auditable and the confidence defensible.

## When It Is NOT This Issue

- **Single-source claim from a vendor with a commercial interest.** It can still be useful, but it is moderate confidence at best until corroborated or observed in your telemetry.
- **Indicator feed with no context.** A list of hashes without campaign, sector, or tooling context is blocklist material, not intelligence.
- **Assessment that restates public reporting.** If the product adds no judgement, it is a news summary; say so rather than dressing it as analysis.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `intelligence requirement` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-intelligence-and-cti` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: threat-intelligence-and-cti
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti-tactical-intelligence`](../threat-intelligence-and-cti-tactical-intelligence/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-intelligence-and-cti-strategic-intelligence`](../threat-intelligence-and-cti-strategic-intelligence/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-intelligence-and-cti` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 28 |
| Distinct dataset sources | 10 |
| Top sources | CYBER_CPT/L5/ctf_search (10), cyber-security/CyberSec-Dataset (6), OffsecCyber (3), Forensic_Toolkit_Dataset (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 2 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
