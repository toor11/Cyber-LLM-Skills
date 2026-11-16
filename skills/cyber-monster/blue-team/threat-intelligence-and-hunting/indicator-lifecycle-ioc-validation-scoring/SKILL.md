---
name: indicator-lifecycle-ioc-validation-scoring
description: IOC validation and confidence scoring. Covers validating indicators for accuracy, assessing freshness and assigning confidence before deployment. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["ioc validation", "ioc confidence", "indicator scoring"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [indicator-lifecycle-and-ioc-management, indicator-lifecycle-ioc-deployment-retirement, threat-intelligence-and-cti, cti-collection-and-enrichment]
parent: indicator-lifecycle-and-ioc-management
---

# Indicator Lifecycle and Ioc Management Ioc Validation and Scoring - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Validation decides whether an indicator is worth deploying; scoring decides how much weight it carries. Validation is about provenance and corroboration - who reported it, whether the observation can be reproduced, and whether the indicator is infrastructure the adversary controls or space they merely used. Scoring combines that with freshness, specificity, and the expected false-positive profile for the observable class, so a shared-hosting IP and a unique file hash never rank the same.

- **CWE-345 framing:** an indicator whose source cannot be authenticated is an integrity risk in the pipeline, not merely a quality issue.
- Observable class drives specificity: hashes and full URLs are highly specific; IPs and bare domains are not, because hosting and registration are reused.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the indicator is already validated and you need deployment or retirement mechanics **THEN** open `indicator-lifecycle-ioc-deployment-retirement`.
2. **IF** the question is how this fits the wider programme **THEN** open `indicator-lifecycle-and-ioc-management`.
3. **IF** the indicator is part of a campaign cluster **THEN** open `diamond-model-and-campaign-clustering` for the infrastructure relationship before scoring it in isolation.
4. **IF** the target narrows to `indicator-lifecycle-and-ioc-management` **THEN** open [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Check provenance first.** Source name, retrieval date, whether the feed is authenticated, and whether the source is primary reporting or a reseller. A reseller chain counts as one source for corroboration.
2. **Test the specificity claim.** For an IP, is it dedicated infrastructure or shared hosting? For a domain, is it registered to the actor or a compromised legitimate site? For a hash, is it unique to the sample or a common loader stub?
3. **Choose the branch on specificity and corroboration.** High specificity plus two sources takes the deploy branch; high specificity plus one source takes the alert-only branch; low specificity takes the context-required branch, where the indicator is only used with an additional condition.
4. **Define the baseline-vs-probe differential.** Baseline: the indicator's observable class over the estate's normal traffic (for an IP, the hosting provider's prevalence). Probe: the same class filtered to the indicator. A score is only meaningful if the baseline prevalence is known.
5. **State the stop condition and the proof.** Stop when every indicator has a provenance record, a specificity assessment, and a score with its rationale; proof is the scoring worksheet for one indicator, not the final number.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| IP on shared bulletproof hosting with 400 other domains | Proves low specificity; blocking it affects other tenants and the actor can move within the same /24. |
| File hash matching a widely used loader stub | Proves the hash is not unique to the campaign, so it will match benign tooling. |
| Domain registered days before the campaign with actor-consistent nameservers | Proves high specificity and actor control; this is deploy-grade infrastructure. |
| Indicator from a reseller feed traced to one upstream | Proves apparent corroboration is one source, which changes the confidence level. |

## Worked Contrast

**Scoring by feed label:**

```yaml
indicator: 203.0.113.44
source: vendor-a
confidence: 90            # copied from the feed's marketing label
action: block
rationale: "vendor rates it high confidence"
```

**Score derived from provenance, specificity, freshness, and prevalence:**

```yaml
indicator: 203.0.113.44
class: ipv4
provenance:
  primary_source: vendor-a (2026-08-02)
  corroboration: [vendor-b 2026-09-11, isac-feed 2026-08-05]
  reseller_chain: false
  feed_authenticated: true
specificity:
  hosting: bulletproof-shared
  co_hosted_domains: 412
  actor_controlled: false          # space used, not owned
  class_specificity: low
prevalence:
  estate_traffic_30d: 3 connections, 1 host, all during the incident
  provider_prevalence: 0.4% of outbound connections
score:
  value: 58/100
  rationale: >
    corroborated by two independent sources and observed once in the estate, but shared hosting
    means blocking carries collateral risk; specificity capped at low.
action: hunt_with_context        # condition: destination AND unusual user-agent required
review: 2026-12-14
```

**Why this matters:** The first record copies a vendor label and blocks shared infrastructure, which creates collateral damage and teaches operators to ignore the blocklist. The second separates provenance from specificity, records the shared-hosting fact that caps the score, measures prevalence in the estate, and converts the finding into a contextual hunt rather than a block.

## When It Is NOT This Issue

- **Low-specificity indicator observed only in your own incident traffic.** Prevalence makes it useful in context even though it is a poor block; the finding would be using it without the context condition.
- **Hash from a signed, legitimate tool abused by the actor.** The hash is not the discriminator; the parent process or path is.
- **Indicator from an unauthenticated OSINT feed.** Useful as a lead; not deployable until corroborated.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `validation` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `indicator-lifecycle-ioc-validation-scoring` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: indicator-lifecycle-ioc-validation-scoring
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-ioc-deployment-retirement`](../indicator-lifecycle-ioc-deployment-retirement/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `indicator-lifecycle-ioc-validation-scoring` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 2 |
| Top sources | CYBER_CPT/ctf_search (5), CYBER_CPT/gh_advisories (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
