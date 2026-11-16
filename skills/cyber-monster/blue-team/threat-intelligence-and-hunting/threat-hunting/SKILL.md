---
name: threat-hunting
description: "Hunts for undetected adversary activity: hypothesis formation, data source selection, query development and converting findings into detections. Use when proactively searching for threats rather than responding to alerts."
family: threat-intelligence-and-hunting
tier: core
triggers: ["threat hunting", "hunt hypothesis", "proactive hunting", "hunting methodology"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-hunting-hypothesis-and-scoping, threat-hunting-hunt-execution-and-triage, threat-hunting-detection-conversion, threat-intelligence-and-cti]
---

# Threat Hunting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Hunting is a structured search for activity you have no alert for, driven by a hypothesis that predicts an observable. The output is a decision about detection coverage rather than a list of hits: each hunt either produces a new rule, confirms a control works, or records a telemetry gap that made the question unanswerable. That last outcome is the most common and the most valuable, because a hunt that cannot be answered is evidence the data you rely on is missing.

- **CWE-778 framing:** most failed hunts are telemetry failures - the field, event, or retention was not there - rather than analytic failures.
- ATT&CK v18 (October 2025) replaced technique detections with Detection Strategies and Analytics and retired Data Sources, so hunting plans should reference the analytics that exist rather than data-source names that no longer do.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the hypothesis is not yet written **THEN** open `threat-hunting-hypothesis-and-scoping`; a hunt without a falsifiable statement becomes browsing.
2. **IF** the hunt has produced candidate logic **THEN** open `threat-hunting-detection-conversion` to turn it into a maintainable rule.
3. **IF** the question is what an actor does rather than what your data contains **THEN** open `threat-intelligence-and-cti-tactical-intelligence` first.
4. **IF** the target narrows to `threat-hunting-hypothesis-and-scoping` **THEN** open [`threat-hunting-hypothesis-and-scoping`](../threat-hunting-hypothesis-and-scoping/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.
5. **IF** the target narrows to `threat-hunting-hunt-execution-and-triage` **THEN** open [`threat-hunting-hunt-execution-and-triage`](../threat-hunting-hunt-execution-and-triage/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.
6. **IF** the target narrows to `threat-hunting-detection-conversion` **THEN** open [`threat-hunting-detection-conversion`](../threat-hunting-detection-conversion/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `threat-hunting-hypothesis-and-scoping` | [`threat-hunting-hypothesis-and-scoping`](../threat-hunting-hypothesis-and-scoping/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `threat-hunting-hunt-execution-and-triage` | [`threat-hunting-hunt-execution-and-triage`](../threat-hunting-hunt-execution-and-triage/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `threat-hunting-detection-conversion` | [`threat-hunting-detection-conversion`](../threat-hunting-detection-conversion/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **State the hypothesis as a prediction about your data.** 'If an affiliate used the appliance access we read about, we will see authentication success from an unusual geography followed by a scheduled-task creation within ten minutes on the same host.' A hypothesis names the observable, the sequence, and the population.
2. **Confirm the data can answer it before writing the query.** Check the event exists, the fields are populated, and retention covers the window. Recording a gap here is a valid hunt outcome and saves the analysis.
3. **Choose the branch on what the hypothesis needs.** Sequence hypotheses take the correlation branch; rare-behaviour hypotheses take the baseline-and-outlier branch; known-indicator hypotheses take the retro-hunt branch.
4. **Define the baseline-vs-probe differential.** Baseline: the same query over a period and population where the behaviour should be absent. Probe: the window and population of interest. A hunt is only conclusive when the baseline is quiet and the probe is not, or both are quiet with adequate coverage.
5. **State the stop condition and the proof.** Stop when the hypothesis is answered yes, no, or unanswerable, with the query, the window, and the coverage statement recorded; proof is the query output plus the data-availability evidence, not the analyst's narrative.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Hypothesis naming an observable, a sequence, and a population | Proves the hunt is falsifiable; without a population the result cannot be generalised. |
| Baseline window quiet and probe window populated | Proves the signal discriminates rather than matching normal activity. |
| Hunt closed as a telemetry gap with the missing field named | Proves the programme learns from coverage instead of recording a false clean result. |
| ATT&CK Detection Strategy referenced in the hunt plan | Proves the plan uses the v18+ analytics model rather than the retired data-source list. |

## Worked Contrast

**Hunt that browses data and produces a hit list:**

```text
Hunt: lateral movement
Query: index=windows EventCode=4624 LogonType=3
Result: 48,201 events, top 20 accounts reviewed
Conclusion: nothing obviously malicious; continue monitoring
Follow-up: none
```

**Hunt with a falsifiable hypothesis, a baseline, and a coverage decision:**

```text
Hypothesis H-2026-31
  If an operator uses credential relay after appliance access, we will see
  NTLM network logons (4624 type 3) on a server that has no NTLM consumer in
  its documented baseline, followed by service creation within 15 minutes.

Population: 412 member servers, 2026-10-01..2026-11-12
Data check: 4624 forwarded from all 412; 7045 forwarded; retention 90d   -> answerable

Baseline (2026-07-01..2026-09-30, before appliance patching):
  17 servers had zero NTLM type-3 logons -> clean baseline list
Probe (hunt window):
  2 of those 17 received NTLM type-3 logons; 1 followed by 7045 in 6 minutes
  host: app-legacy-03, account: svc-backup, service: 'WinDefendSvc'

Outcome: 1 confirmed malicious chain -> IR-2026-118
Detection: new rule for NTLM type-3 on baseline-clean servers (converted, see rule 88f1)
Coverage note: 7045 missing on 9 OT hosts -> telemetry ticket SEC-6710
```

**Why this matters:** The first hunt states a technique, filters by a common logon type, and produces a number too large to analyse, so the conclusion is an impression. The second predicts a specific pattern, proves the data can answer it, derives a baseline list of servers that never use NTLM, and finds the exception - then converts it to a rule and records the telemetry gap that limited coverage.

## When It Is NOT This Issue

- **Zero results treated as proof of absence.** Only conclusive if the data check passed for the full population and window; otherwise it is a coverage statement.
- **Alert triage dressed as a hunt.** Reviewing existing alerts is triage; a hunt starts from a hypothesis and looks for activity no alert covers.
- **Threat feed keyword search.** Searching for a vendor's indicator list is retro-hunting, which is useful but narrower than hypothesis-driven hunting and should be labelled as such.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `hypothesis` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-hunting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: threat-hunting
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-hunting-hypothesis-and-scoping`](../threat-hunting-hypothesis-and-scoping/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-hunting-hunt-execution-and-triage`](../threat-hunting-hunt-execution-and-triage/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-hunting-detection-conversion`](../threat-hunting-detection-conversion/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-hunting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 32 |
| Distinct dataset sources | 10 |
| Top sources | SecEval/attck (8), cyber-security/CyberSec-Dataset (7), CYBER_CPT/L5/ctf_search (6), CYBER_CPT/ctf_search (3) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 2 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
