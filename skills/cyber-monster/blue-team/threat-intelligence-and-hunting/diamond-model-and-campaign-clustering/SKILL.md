---
name: diamond-model-and-campaign-clustering
description: "Clusters intrusion sets objectively using the Diamond Model (Adversary, Capability, Infrastructure, Victim) and estimative probability language: separating infrastructure-broker reuse from true actor attribution and documenting competing hypotheses (ACH). Use when analyzing multi-incident campaigns."
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["diamond model cti", "analysis of competing hypotheses", "intrusion set clustering", "estimative language cti"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management, threat-hunting]
corpus_sparse: true
---

# Diamond Model and Campaign Clustering - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

The Diamond Model gives four vertices - adversary, capability, infrastructure, and victim - and two axes, social-political and technical, so an incident can be described as an event with relationships rather than a list of indicators. Clustering is the practice of pivoting along those edges: shared infrastructure links capabilities, shared capabilities link victims. Analysis of Competing Hypotheses is the discipline that keeps the clustering honest, because shared commodity tooling produces clusters that look convincing and are several actors.

- **CWE-345 framing:** clustering on unvalidated indicators propagates errors into every downstream product, so each vertex entry carries its source and confidence.
- A shared indicator is not a shared actor: infrastructure is rented, tooling leaks, and builders are resold.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is who rather than what cluster **THEN** open `adversary-tracking-and-attribution` for the judgement framework.
2. **IF** the goal is a detection from the capability vertex **THEN** open `threat-hunting-detection-conversion`.
3. **IF** the goal is an intelligence product for a consumer **THEN** open `threat-intelligence-and-cti-tactical-intelligence`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Populate the four vertices per incident before pivoting.** Adversary (even if unknown), capability (malware, tooling, exploit), infrastructure (C2, hosting, certificates), victim (sector, region, profile). Record confidence per entry.
2. **Pivot along one edge at a time.** Capability to capability through shared code or config; infrastructure to infrastructure through certificates or registration; victim to victim through targeting pattern. Note which edge produced each link.
3. **Choose the branch on edge strength.** Unique artefact edges take the cluster branch; commodity edges take the watchlist branch; single-edge clusters take the hypothesis branch pending a second edge.
4. **Define the baseline-vs-probe differential.** Baseline: the prevalence of each edge in the wider corpus. Probe: the same edge within the candidate cluster. A cluster justified only by a high-prevalence edge is a tooling family, not a campaign.
5. **State the stop condition and the proof.** Stop when every cluster has at least two independent edge types and a competing-hypothesis note; proof is the pivot path from one incident to another, with each edge's prevalence.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Cluster joined by certificate serial pattern and C2 config | Proves two independent edge types, which is the minimum for a campaign claim. |
| Cluster joined only by a shared loader | Proves a tooling family; the loader is commodity and appears across many actors. |
| Victim-to-victim edge with identical targeting and timing | Proves operational linkage when combined with another edge; alone it is sector preference. |
| Competing hypothesis recorded as a different actor with shared tooling | Proves ACH was applied, which is what distinguishes analysis from pattern matching. |

## Worked Contrast

**Clustering by shared indicators only:**

```text
Cluster A (18 indicators)
- 4 domains resolved to the same /24
- all samples use the same loader
- both victims are logistics companies
Conclusion: one campaign, actor named as APT-Y.
```

**Diamond vertices with edge type and prevalence per link:**

```text
Incident 1 -> Incident 2 pivot

vertex: capability
  link: same loader family (commodity, prevalence 34% of corpus)      edge strength: weak
  link: same C2 profile (sleep 47s, jitter 23%, watermark 0x1a2b)     edge strength: strong (1.2%)
vertex: infrastructure
  link: same /24 203.0.113.0/24                                        edge strength: moderate (hosting resold)
  link: same self-signed cert serial pattern, 63-day life             edge strength: strong (0.4%)
vertex: victim
  link: same sub-sector, same region, both intrusions 02:00-04:00 local  edge strength: weak alone

Cluster claim: two independent strong edges (C2 profile, cert pattern) plus one moderate
ACH:
  H1 one cluster                  - explains all edges
  H2 shared builder, two actors    - explains loader and C2 profile defaults, not the cert pattern
  H3 resold hosting with copied config - explains infrastructure, not the C2 profile
Verdict: H1 most likely (moderate confidence); H2 not excluded without builder telemetry.
```

**Why this matters:** The first cluster is built from a commodity loader and a shared /24, both of which are high-prevalence, so the conclusion merges unrelated actors. The second records each edge with its type and prevalence, requires two independent strong edges, and states which hypothesis survives - which is the difference between a cluster and a pattern match.

## When It Is NOT This Issue

- **Shared hosting /24.** Resold hosting puts unrelated actors on adjacent addresses; it is a weak edge.
- **Same malware family.** Families are sold, leaked, and reused; the family is a capability label, not an actor label.
- **Same victim sector.** Targeting preference is broad and stable across many actors.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `Diamond Model vertex` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `diamond-model-and-campaign-clustering` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: diamond-model-and-campaign-clustering
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `diamond-model-and-campaign-clustering` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
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
