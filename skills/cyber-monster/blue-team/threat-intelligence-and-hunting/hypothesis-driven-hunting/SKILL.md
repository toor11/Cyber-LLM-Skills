---
name: hypothesis-driven-hunting
description: Develops and tests specific hunt hypotheses tied to ATT&CK techniques and threat actor behaviour, with measurable outcomes. Use when a hunt needs structure beyond ad hoc searching.
family: threat-intelligence-and-hunting
tier: core
triggers: ["hunt hypothesis", "hypothesis driven", "structured hunting"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management, threat-hunting]
---

# Hypothesis Driven Hunting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

A hypothesis is the instrument that keeps a hunt bounded: it states what would be observed if a specific adversary behaviour were present, which populations would show it, and what observation would falsify it. Good hypotheses come from three places - a technique you cannot currently detect, an intelligence report about your sector, or an anomaly in your own baseline - and they are ranked by the cost of being wrong, because that is what determines whether the hunt is worth running now.

- **CWE-778 framing:** a hypothesis that cannot fail is a description of normal activity; the falsification condition is the analytic control.
- ATT&CK v19 split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112), so hypotheses phrased against 'defense evasion' should be re-expressed against the specific intent.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the hypothesis is written and you need to execute it **THEN** open `threat-hunting-hunt-execution-and-triage`.
2. **IF** the hypothesis derives from a technique without coverage **THEN** check `threat-hunting-detection-conversion` for what already exists before duplicating it.
3. **IF** the source is an intelligence report about a specific actor **THEN** open `threat-intelligence-and-cti-tactical-intelligence` to extract the observable first.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Write the hypothesis in the if-then-because form.** 'If <behaviour> occurred, then <observable> would appear in <data source> for <population>, because <mechanism>.' The mechanism clause is what makes it testable and explains why the data source is the right one.
2. **State the falsification condition explicitly.** What result would show the behaviour is absent, and what coverage is needed for that absence to be meaningful. Without it, every null result is ambiguous.
3. **Choose the branch on the hypothesis source.** Coverage-gap hypotheses take the technique branch; intelligence hypotheses take the actor-observable branch; anomaly hypotheses take the baseline branch.
4. **Define the baseline-vs-probe differential before running.** Baseline population and window, probe population and window, and the expected difference in counts or shape. Writing this first prevents post-hoc reasoning.
5. **State the stop condition and the proof.** Stop when the falsification condition is evaluated against adequate data, and record outcome, data adequacy, and any coverage gap; proof is the hypothesis record with its query, windows, and result classification.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Hypothesis naming a mechanism, not only a technique | Proves the hunt has a causal model; 'if T1053 occurs' is a technique, not a hypothesis. |
| Falsification condition with a coverage requirement | Proves null results can be interpreted; without coverage the result is unanswerable, not negative. |
| Ranking by cost of being wrong | Proves prioritisation is about consequence, so a low-probability high-impact hypothesis outranks a high-probability cosmetic one. |
| Hypothesis linked to an ATT&CK Detection Strategy or an existing gap | Proves the hunt is not duplicating coverage that already exists in the detection library. |

## Worked Contrast

**Hypothesis that cannot fail:**

```text
Hunt idea: look for suspicious PowerShell
Data: PowerShell logs
Query: EventCode=4104 AND (encoded OR downloadstring OR bypass)
Expected: some hits, review them
```

**Hypothesis with a mechanism, a population, and a falsification condition:**

```text
H-2026-42
If an operator stages a payload using a signed interpreter proxy
(signed binary -> script host -> outbound fetch), then within the same
process tree we will see a network connection owned by a process whose
parent is an Office application, for workstations in the finance OU,
because proxy execution avoids unsigned-binary blocks.

Data: sysmon EID 3 + 1 with parent image, 90-day retention, 100% of finance workstations
Population: 240 workstations, finance OU, business hours
Baseline (2026-08-01..2026-09-30): 0 connections with Office parentage in this population
Probe (2026-10-01..2026-11-12): expected >0 if the behaviour exists

Falsification: zero qualifying connections across the full population and window
  with both EID 1 and EID 3 coverage verified => behaviour absent (or not attempted)

Ranking: high cost of being wrong (finance), low baseline noise, data adequate -> run now
```

**Why this matters:** The first idea names a technique, a broad query, and an expectation of 'some hits', so no result can falsify it and the analyst learns nothing. The second names the mechanism, the population, the baseline, and the condition that would disprove it - plus a coverage requirement, which is what makes a null result meaningful.

## When It Is NOT This Issue

- **Hypothesis phrased as a technique id.** A technique is a category; the hypothesis needs the mechanism and the observable it produces in your environment.
- **Hypothesis with no baseline.** Without a baseline the probe result cannot be judged anomalous, and the hunt becomes a query review.
- **Re-running an existing rule as a hunt.** Check the detection library first; duplication wastes the window and produces false confidence in coverage.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `hypothesis statement` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `hypothesis-driven-hunting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: hypothesis-driven-hunting
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
- [`adversary-tracking-and-attribution`](../adversary-tracking-and-attribution/SKILL.md) - Threat Intelligence and Hunting (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `hypothesis-driven-hunting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/go_exploitdb (6) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
