---
name: indicator-lifecycle-and-ioc-management
description: "Manages indicators across their lifecycle: ingestion, validation, scoring, deployment to controls and retirement. Use when maintaining IOC feeds and blocklists."
family: threat-intelligence-and-hunting
tier: core
triggers: ["ioc management", "indicator lifecycle", "ioc scoring", "blocklist management"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [indicator-lifecycle-ioc-validation-scoring, indicator-lifecycle-ioc-deployment-retirement, threat-intelligence-and-cti, cti-collection-and-enrichment]
---

# Indicator Lifecycle and Ioc Management - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Indicator management is a lifecycle, not a list: an indicator is created with a confidence and an expected lifetime, deployed where it can be evaluated, scored by its hit rate against known-good activity, and retired when it stops discriminating. The failure mode is accumulation - a blocklist that only grows teaches operators to ignore alerts and eventually breaks legitimate traffic. Every stage needs a number, because 'still relevant' is not a state you can act on.

- **CWE-200 / CWE-345:** an indicator that leaks internal context, or one whose provenance cannot be checked, is a liability rather than an asset.
- TTL is a property of the observable type: file hashes age slowly, domains and IPs age quickly, and infrastructure indicators age fastest of all because hosting is reused.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the question is how to validate or score a specific indicator **THEN** open `indicator-lifecycle-ioc-validation-scoring`.
2. **IF** the question is deployment or retirement mechanics **THEN** open `indicator-lifecycle-ioc-deployment-retirement`.
3. **IF** the consumer wants detection content rather than an indicator **THEN** open `threat-hunting-detection-conversion`, since a behaviour rule outlives an indicator.
4. **IF** the target narrows to `indicator-lifecycle-ioc-validation-scoring` **THEN** open [`indicator-lifecycle-ioc-validation-scoring`](../indicator-lifecycle-ioc-validation-scoring/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.
5. **IF** the target narrows to `indicator-lifecycle-ioc-deployment-retirement` **THEN** open [`indicator-lifecycle-ioc-deployment-retirement`](../indicator-lifecycle-ioc-deployment-retirement/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `indicator-lifecycle-ioc-validation-scoring` | [`indicator-lifecycle-ioc-validation-scoring`](../indicator-lifecycle-ioc-validation-scoring/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `indicator-lifecycle-ioc-deployment-retirement` | [`indicator-lifecycle-ioc-deployment-retirement`](../indicator-lifecycle-ioc-deployment-retirement/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Classify the observable before assigning a lifetime.** Hash, domain, IP, URL path, certificate, or behaviour. The class sets the default TTL and the expected false-positive profile.
2. **Score on discrimination, not on count.** For each indicator track hits, distinct assets, and how many hits were later judged benign. An indicator with hits only on known-good infrastructure is negative value.
3. **Choose the branch on the score.** High discrimination takes the keep-and-extend branch; ambiguous takes the narrow-the-scope branch (add a context condition); noise takes the retire branch; unvalidated takes the hold branch with no deployment.
4. **Define the baseline-vs-probe differential.** Baseline: hit rate over the last cycle against known-good activity. Probe: re-deploy the indicator in alert-only mode for one cycle and compare. A retired indicator should show no unique value when re-probed.
5. **State the stop condition and the proof.** Stop when every indicator has a class, a TTL, a hit-rate record, and a disposition; proof is the hit-rate history for one retired and one retained indicator.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| IP indicator with hits only from your own scanning infrastructure | Proves negative discrimination; the indicator matches authorised activity and will generate noise forever. |
| Domain indicator still matching months after the campaign ended | Proves TTL is not enforced, and the domain may now be sinkholed or resold. |
| Hash indicator with zero hits across the estate | Proves either good prevention or an undeployable indicator; check which sensor would have seen it. |
| Indicator without a source recorded | Proves provenance loss, which makes scoring and legal sharing impossible. |

## Worked Contrast

**Blocklist that grows without scoring or retirement:**

```text
indicator_store (append-only)
  18,402 -> 24,118 -> 31,760 entries over 6 months
  fields: value, added_at
  no hit tracking, no TTL, no source
alert volume: 1,240/day, 3 closed as incidents
analyst behaviour: filters the IOC alert queue by default
```

**Lifecycle store with scoring, scoped deployment, and retirement evidence:**

```text
indicator 203.0.113.44  class=ipv4  source=vendor-a  first_seen=2026-08-02
  deployed: dns-proxy (alert), edge-fw (block)   scope=outbound
  hits: 12 across 3 assets; 9 correlated to one incident; 3 from scanner range -> excluded
  discrimination: high (unique to one campaign, no benign match after exclusion)
  ttl: 30d  review: 2026-12-02  action: keep, narrow edge block to non-scanner sources

indicator old-c2.example.net  class=domain  source=vendor-b  first_seen=2026-03-01
  deployed: dns-proxy (alert)
  hits: 0 in 90d; 2 benign hits in March from a marketing redirect
  discrimination: none
  ttl: expired  action: retire; keep in TI store for retro-hunts only
```

**Why this matters:** The first store only grows, tracks nothing, and trains analysts to filter its alerts, so the programme pays for collection and receives nothing. The second records the class and source, scopes deployment per sensor, excludes the scanner range from the hit count, and retires an indicator with the evidence that it no longer discriminates - which is what keeps the remaining alerts meaningful.

## When It Is NOT This Issue

- **Indicator with zero hits because the sensor does not cover that path.** That is a coverage gap in the deployment, not evidence the indicator is worthless.
- **Hash with a long TTL.** File hashes do not change once the sample exists, so a long life is correct for that class.
- **Low hit count on a high-value indicator.** Rarity can be the point; score on correlation to incidents rather than on volume alone.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `IOC` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `indicator-lifecycle-and-ioc-management` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: indicator-lifecycle-and-ioc-management
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`indicator-lifecycle-ioc-validation-scoring`](../indicator-lifecycle-ioc-validation-scoring/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`indicator-lifecycle-ioc-deployment-retirement`](../indicator-lifecycle-ioc-deployment-retirement/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `indicator-lifecycle-and-ioc-management` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 17 |
| Distinct dataset sources | 7 |
| Top sources | CYBER_CPT/L5/ctf_search (4), OffsecCyber (3), cyber-security/CyberSec-Dataset (3), CYBER_CPT/github_security_md (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
