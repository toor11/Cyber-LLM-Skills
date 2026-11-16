---
name: threat-intelligence-and-cti-strategic-intelligence
description: "Strategic threat intelligence. Covers high-level intelligence for decision makers: actor trends, risk posture and sector targeting, with appropriate confidence language. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["strategic threat intel", "executive threat briefing", "risk intelligence"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, threat-intelligence-and-cti-tactical-intelligence, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management]
parent: threat-intelligence-and-cti
---

# Threat Intelligence and CTI Strategic Intelligence - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Strategic intelligence informs a decision about posture, investment, or risk appetite over a horizon of quarters rather than days. It is judged on whether it changed a plan: a control funded, a risk accepted, a sector assumption revised. The discipline is honesty about uncertainty - a strategic product that hides its confidence behind confident prose is worse than no product, because it launders an assumption into a budget line.

- **CWE-200 framing:** strategic products often aggregate incident details that should not circulate beyond a need-to-know; classification and audience are part of the product.
- Sector reporting frequently over-weights victim disclosure; state the sampling bias rather than presenting it as prevalence.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the consumer needs technique-level detail **THEN** open `threat-intelligence-and-cti-tactical-intelligence`.
2. **IF** the request is a sector benchmark **THEN** open `sector-threat-landscape-analysis`.
3. **IF** the decision is a risk treatment choice **THEN** pair this with `risk-assessment-and-treatment` so the product lands in the register.
4. **IF** the target narrows to `threat-intelligence-and-cti` **THEN** open [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Name the decision and the horizon.** Investment in a control, a risk acceptance, or a change to assumed likelihood. The horizon sets the evidence window and the level of detail.
2. **Separate what is known from what is inferred.** Evidence lines with sources and dates; inference lines with the reasoning. A reader must be able to disagree with the inference without rejecting the evidence.
3. **Choose the branch on the decision type.** Investment decisions take the likelihood-and-impact branch; risk acceptance takes the exposure branch; posture changes take the capability-gap branch.
4. **Define the baseline-vs-probe differential.** Baseline: the assumption the organisation currently plans against. Probe: what the product asserts instead. State the delta explicitly, because a product that confirms existing assumptions needs no decision.
5. **State the stop condition and the proof.** Stop when the product names the decision, the delta from the current assumption, the confidence, and the reasoning; proof is the decision record that cites it, or an explicit note that no decision was taken.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Product stating the delta from the current planning assumption | Proves the product can change a decision; a product that confirms the assumption has no customer. |
| Confidence expressed with its basis in source quality | Proves calibration; low-quality sources cap confidence regardless of volume. |
| Sampling bias stated for sector prevalence claims | Proves the analysis distinguishes reported victims from actual prevalence. |
| Decision record citing the product | Proves the loop closed; without it the product is an artefact with no consumer. |

## Worked Contrast

**Strategic product that reports activity and recommends vigilance:**

```text
Threat Landscape Q4 2026
Ransomware continues to rise across all sectors.
Nation-state activity remains elevated.
Our sector is increasingly targeted.
Recommendation: maintain investment in security controls and stay informed.
```

**Strategic product with a delta, a confidence basis, and a decision:**

```text
Decision: FY27 control investment priority   Horizon: 12 months   Audience: CISO + finance
Current planning assumption: edge appliances are patched quarterly and the residual risk is accepted.

Assessment (moderate confidence)
  The assumption is stale for the 9 appliances without management-plane MFA. Reporting from two
  vendors and our own exposure data indicate that is the entry path actually being used against
  organisations of our profile, not a theoretical one.

Delta from the assumption
  Quarterly patching remains adequate for the patched set.
  For the 9 unpatched-MFA appliances, the exposure is continuous, not quarterly.

Evidence
  2 vendor reports (Aug-Sep 2026) on affiliate initial access via VPN appliances
  internal exposure scan 2026-10-28: 9 of 41 appliances without MFA
  sector ISAC bulletin 2026-10: 4 members reported the same access vector

Sampling bias
  Victim disclosure over-represents organisations with incident response retainers; true
  prevalence is likely higher, not lower.

Recommendation and cost
  Move MFA rollout for those 9 appliances into Q1 rather than Q3; estimated 40 engineering hours,
  no licence change.

Confidence: moderate - vendor reporting not independently artefacted; internal exposure is confirmed.
```

**Why this matters:** The first product reports trends and recommends what the organisation is already doing, so no decision follows. The second names the current assumption, states precisely which part of it is wrong, quantifies the delta with internal evidence, discloses the sampling bias in the sector claim, and prices the recommendation - which is what makes it usable in a budget conversation.

## When It Is NOT This Issue

- **Product confirming the existing plan.** Useful as assurance but not a decision input; label it as assurance rather than presenting it as new intelligence.
- **Sector prevalence from victim disclosures.** State the bias; do not present reporting volume as incidence.
- **Assessment outside the organisation's exposure.** Actor trends that cannot reach your estate belong in monitoring, not in an investment case.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `actor trend` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-intelligence-and-cti-strategic-intelligence` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: threat-intelligence-and-cti-strategic-intelligence
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-intelligence-and-cti-tactical-intelligence`](../threat-intelligence-and-cti-tactical-intelligence/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-intelligence-and-cti-strategic-intelligence` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/cybereason (2), CYBER_CPT/wiz_research (1), CYBER_CPT/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 4 cases |
| Grounding | multi-dataset corpus-grounded |
