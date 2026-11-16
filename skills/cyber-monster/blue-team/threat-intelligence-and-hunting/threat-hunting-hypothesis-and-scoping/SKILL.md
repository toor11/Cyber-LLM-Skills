---
name: threat-hunting-hypothesis-and-scoping
description: Hunt hypothesis and scoping. Covers turning intelligence or gaps into a testable hunt hypothesis with clear data requirements and success criteria. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["hunt scoping", "hunt hypothesis formulation"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-hunting, threat-hunting-hunt-execution-and-triage, threat-hunting-detection-conversion, threat-intelligence-and-cti]
parent: threat-hunting
corpus_sparse: true
---

# Threat Hunting Hypothesis and Scoping - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Scoping is the part of hunting that decides what the answer will be allowed to mean: which hosts, accounts, and time windows are in, which telemetry is expected to cover them, and what result would count as evidence either way. A hunt scoped too widely produces a result nobody can analyse; scoped too narrowly it produces a clean result that says nothing about the estate. The scope record is what makes the difference visible later, when someone asks whether the hunt covered their system.

- **CWE-778 framing:** the scope record is also the coverage record, so a missing field here becomes an uninterpretable null later.
- Scope must name retention explicitly: a 90-day hypothesis over 30-day retention is unanswerable for two thirds of its window.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the hypothesis is not written **THEN** start at `hypothesis-driven-hunting` for the statement, then come here to bound it.
2. **IF** the scope is already fixed and you need to run the queries **THEN** open `threat-hunting-hunt-execution-and-triage`.
3. **IF** the scoping question is really an inventory question **THEN** open `asset-inventory-and-cmdb`, because scope drawn from a stale inventory is the most common silent error.
4. **IF** the target narrows to `threat-hunting` **THEN** open [`threat-hunting`](../threat-hunting/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`threat-hunting`](../threat-hunting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Define the population from the inventory, then subtract the excluded classes explicitly.** Hosts, accounts, and network segments, with the exclusion reason. A count is mandatory, because 'all servers' is not a population.
2. **Verify telemetry coverage for that exact population.** Which sensor, which event, and whether every host reports it. A host without the sensor is outside the scope in practice, whatever the spreadsheet says.
3. **Choose the branch on the coverage result.** Full coverage takes the direct-query branch; partial coverage takes the endpoint-collection branch for the gaps; no coverage takes the coverage-ticket branch and the hunt is deferred rather than run.
4. **Define the baseline-vs-probe differential while scoping.** Same population, two windows, one before the activity of interest. Recording it here prevents a later analyst from choosing a flattering baseline.
5. **State the stop condition and the proof.** Stop when the scope record names population, coverage, windows, and exclusions; proof is a per-host coverage count for the event the hypothesis needs.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Scope with a host count and an exclusion list | Proves the population is defined; hunts without counts cannot report a rate or a coverage figure. |
| Per-host event coverage check | Proves the telemetry claim; a sensor gap silently turns an answerable hunt into a null result. |
| Retention versus window comparison | Proves the window is answerable; a shorter retention makes the hypothesis untestable for part of its range. |
| Baseline window recorded before the probe window | Proves the comparison was designed rather than selected after seeing results. |

## Worked Contrast

**Scope described in prose with no counts or coverage check:**

```text
Scope: all Windows servers and workstations
Timeframe: the last few months
Data: our SIEM
Exclusions: test machines
Expected result: hopefully nothing
```

**Scope with counts, coverage, retention, and designed windows:**

```text
population
  servers       412  (inventory 2026-11-13, excludes 6 decommissioning)
  workstations 1,995 (excludes 15 kiosks, reason: no EDR)
telemetry
  event  sched task creation (EID 4698/106)
  sensor windows-security-log forwarded via agent
  coverage 405/412 servers, 1,912/1,995 workstations -> 19 gaps listed in coverage-gaps.txt
  retention 90d (oldest available 2026-08-16)
windows
  baseline 2026-08-16..2026-09-30   (retention-bounded, stated)
  probe    2026-10-01..2026-11-13
exclusions
  build agents (34 hosts) reason: deploy tasks by design   owner: ci-platform
  kiosks (15)             reason: no agent                     owner: workplace
falsification
  zero qualifying events across covered hosts and full window with the 19 gaps treated as unanswerable
interpretation
  a clean result covers 98.3% of the intended population; the 19 gaps are reported separately
```

**Why this matters:** The first scope cannot be reported on: there is no count, no coverage claim, no retention check, and 'hopefully nothing' is not a result. The second states counts from a dated inventory, quantifies coverage and lists the gaps, ties the baseline window to retention, records exclusions with owners, and pre-commits to how a clean result will be interpreted - which is what makes the hunt defensible.

## When It Is NOT This Issue

- **Exclusion of build agents from task-creation hunting.** CI systems create scheduled tasks by design; excluding them is correct when the reason and owner are recorded.
- **Coverage below 100% on a large estate.** Partial coverage is normal; the finding is reporting a clean result without stating the covered fraction.
- **Baseline shorter than the probe because retention is short.** That is a limitation to record, not a reason to skip the baseline.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `hypothesis` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-hunting-hypothesis-and-scoping` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: threat-hunting-hypothesis-and-scoping
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting-hunt-execution-and-triage`](../threat-hunting-hunt-execution-and-triage/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-hunting-detection-conversion`](../threat-hunting-detection-conversion/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-hunting-hypothesis-and-scoping` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
