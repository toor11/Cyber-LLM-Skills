---
name: security-metrics-and-detection-coverage
description: "Measures security operations performance: MTTD and MTTR, coverage percentages, alert quality metrics and reporting to stakeholders. Use when quantifying detection program effectiveness."
family: detection-and-monitoring
tier: core
triggers: ["security metrics", "mttd", "mttr", "detection coverage metric", "soc metrics"]
cwe: [CWE-778]
owasp: []
attack: []
capec: [CAPEC-116]
related: [detection-engineering, sigma-rule-authoring, yara-rule-authoring, siem-query-and-log-analysis]
corpus_sparse: true
---

# Security Metrics and Detection Coverage - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Detection and Monitoring`](../README.md) | Tier: **core** | Paired Counterpart: [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Every metric in this leaf is a ratio whose numerator and denominator are separately constructed, and almost all reporting error comes from leaving one of them implicit. MTTD is only meaningful when "detected" is anchored to the earliest evidence of compromise rather than to alert creation — measured from the alert, it improves whenever triage gets slower to escalate, which is the opposite of what it claims. Coverage is only meaningful with a stated denominator (the techniques relevant to this estate), a stated framework version (v19 moved Defense Evasion into Stealth and Defense Impairment, so pre-v19 rows are not comparable), and a stated proof tier: a rule present in a catalogue, a rule deployed and enabled, a rule whose Data Component is collected and passing its contract, and a rule proven to fire against a real or emulated technique are four different numbers. Precision must be tracked alongside volume, because suppressing alerts raises every other metric without improving detection.

- **CWE-778 (Insufficient Logging):** When a security-critical event occurs, the product either does not record the event or omits important details about the event when logging it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a metric is requested without a named denominator **THEN** state the denominator you are using before producing the number, and name what it excludes.
2. **IF** MTTD can be computed from the alert timestamp only **THEN** label it `alert-to-analysis` and do not publish it as MTTD; **IF** retrospective first evidence exists from triage notes or log review **THEN** use that and say so.
3. **IF** the coverage figure comes from rule tags alone **THEN** report it as `library` or `deployed` tier and never as validated; **IF** emulation results exist **THEN** report the `validated` tier separately rather than blending them.
4. **IF** a data source feeding a mapped technique is failing its freshness or null-rate contract **THEN** remove that technique from the covered set before publishing.
5. **IF** the metric window's underlying data crosses a retention boundary **THEN** shorten the window or report the period as partially observed — never extrapolate a truncated window into a full period.
6. **IF** telemetry source covering the incident timeline behind `MTTD` or `MTTR` is missing, disabled, or uncollected **THEN** report `INCONCLUSIVE (Telemetry Gap)` — NEVER report `Clean/Benign`.
7. **IF** you need the underlying offensive mechanics or audit preconditions **THEN** pivot directly to paired Red skill [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md).

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need metric queries over ticketing and alert data | [`QUERIES.md`](QUERIES.md) | MTTD/MTTR arithmetic, precision, coverage and staleness classes |
| Need tooling for layers and score history | [`TOOLS.md`](TOOLS.md) | DeTT&CT score logs, Navigator layers, coverage scripts |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | What to do when a metric reveals a gap mid-incident |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |
| Need the technique-to-rule mapping itself | [`mitre-attack-mapping`](../mitre-attack-mapping/SKILL.md) | Mapping methodology belongs there, not here |
| Need rule quality rather than counts | [`detection-engineering`](../detection-engineering/SKILL.md) | Rule lifecycle and review standards |

## Procedure

1. **Confirm the data sources behind each metric.** For MTTD and MTTR you need ticket state transitions with timestamps, and for coverage you need the rule inventory, the mapping, and per-source contract results. If any of the three is absent, the honest output is a smaller metric set, not an estimate.
2. **Choose the reporting branch: point-in-time health versus trend.** Health answers "are we covered now" and needs the current validated set. Trend answers "are we improving" and needs the same computation applied to historical snapshots, which only exists if you stored the inputs. Pick one and say which.
3. **Define the baseline-versus-probe differential in metric terms.** Compare the metric over the current period against the prior period computed identically, and against a peer group or tier where one exists. A percentage with no comparison is not a finding; the movement is.
4. **Name the stop condition.** Stop and declare the metric partial when the ticket system changed schema mid-period, when a rule corpus migration broke tag continuity, when the framework version changed inside the comparison window, or when the source feeding a mapped technique failed its contract. Do not splice incomparable periods to fill a chart.
5. **State what counts as proof.** Proof for MTTD is an incident where the first-evidence timestamp is documented and independently checkable against the logs. Proof for coverage is a rule that fired on a real or emulated instance of the technique with its Data Component passing contract gates. Neither is provable from a tag count.

## Concrete Patterns

| Indicator / Artifact | Query class | What it proves |
|---|---|---|
| `percentile(first_alert - first_evidence, 50/95)` over closed incidents | MTTD | Detection latency distribution, not a mean that one slow incident can dominate |
| Incidents closed with no detection attributable to the estate | MTTD (undetected set) | The coverage-failure signal, which must be reported separately from detected-case MTTD |
| `summarize count() by state` over ticket transitions | MTTR | Where time is actually spent: triage, containment, or waiting on approval |
| Rules with zero alerts in 90 days and no passing test fixture | staleness | Rules that either never fire or no longer fire, both of which inflate coverage without adding it |
| `true_positives / worked_alerts` per rule | precision | Whether a coverage row is a working detection or a noise generator |
| Techniques with a deployed rule whose Data Component fails contract | coverage tier | The gap between `deployed` and `collected`, which is where most published coverage is lost |
| Technique count with an emulation pass inside the period | validated coverage | The only tier that survives an auditor's "prove it fires" question |
| Median days from technique publication to deployed detection | time-to-coverage | Programme responsiveness to framework change, especially across the v18-to-v19 relabel |

## Worked Contrast

**Weak / Noisy Reporting Practice:**

```text
# WEAK: the number everyone quotes and nobody can defend.
coverage = rules_tagged_with_attack / 222          # denominator is the whole catalogue
mttd      = avg(alert_created - incident_created)  # measured from the alert
precision = suppressed_alerts / total_alerts        # suppression counted as quality
# Reported quarterly with no ATT&CK version, no proof tier, no denominator note.
```

**High-Signal Grounded Reporting:**

```text
# STRONG: same programme, four defensible lines.
1. validated_coverage = techniques_emulation_passed / techniques_relevant
   denominator: 87 techniques relevant to this estate   framework: ATT&CK v19
2. collected_coverage = techniques_with_contract_passing_source / techniques_relevant
   note: 9 techniques lost here because the EDR table null-rate regressed on 2026-10-02
3. mttd_p50 / mttd_p95 computed from first_evidence (documented per incident),
   with the undetected cohort reported as its own line and excluded from the average
4. precision per rule = tp / worked, used to decide retirement, never to claim improvement
```

**Why this matters:** the weak form produces figures that move when irrelevant things change — suppression raises precision, a new alert format raises MTTD, and a framework release moves coverage without any engineering. The strong form fixes the denominator, names the framework version, separates collected from validated, and reports the undetected cohort rather than averaging it away.

## When It Is NOT This Issue

- **Ticket schema migration mid-period:** a workflow change that renames or resets state transitions makes MTTR jump or drop with no operational change. The comparison is invalid, not the programme.
- **A rule corpus migration that breaks tag continuity:** re-importing rules with new IDs or a changed tag convention makes coverage appear to collapse overnight. Check tag provenance before escalating.
- **Framework version change inside the comparison window:** v19 merging `T1562` into `T1685` and splitting Defense Evasion into Stealth and Defense Impairment re-labels rows without any detection changing.
- **Suppression mistaken for tuning:** disabling noisy rules raises precision and lowers volume while removing detection. Any precision improvement must be reported with the coverage delta beside it.
- **Denominator shopping:** a coverage figure that improved because the relevant-technique list was shortened is a scope change, not engineering progress. Compare denominator sizes period over period.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER publish a coverage percentage without its denominator, ATT&CK version and proof tier.**
- **NEVER present a truncated or schema-broken period as a full-period metric** — label it partial and name the boundary.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `MTTD` / `MTTR` inputs was disabled, rotated out, or uncollected.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Evidence source confirmed:** the ticket transitions, rule inventory and per-source contract results behind each metric were located, not assumed to exist.
- [ ] **Denominator and framework pinned:** the relevant-technique count and the ATT&CK release are stated with the number.
- [ ] **Differential defined:** the current period was compared against a prior period computed identically, or the comparison was declared impossible.
- [ ] **Stop condition stated:** schema migration, tag discontinuity, framework change or contract failure was named where it applied.
- [ ] **Proof standard met:** MTTD rows carry a documented first-evidence timestamp; coverage rows carry a fired rule or are labelled below the validated tier.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: security-metrics-and-detection-coverage
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-778 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`adversary-emulation-planning`](../../../red-team/osint-and-red-operations/adversary-emulation-planning/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`detection-engineering`](../detection-engineering/SKILL.md) - Detection and Monitoring (flagship)
- [`sigma-rule-authoring`](../sigma-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`yara-rule-authoring`](../yara-rule-authoring/SKILL.md) - Detection and Monitoring (core)
- [`siem-query-and-log-analysis`](../siem-query-and-log-analysis/SKILL.md) - Detection and Monitoring (core)
- [`log-source-onboarding-and-parsing`](../log-source-onboarding-and-parsing/SKILL.md) - Detection and Monitoring (core)

## Operating Notes

- **A ratio is two decisions:** numerator and denominator are each a choice. Publish both, or the number is a claim about your definitions rather than about your detection.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-778`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope; metrics work is read-only over ticketing and rule inventories.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/wiz_research (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
