---
name: threat-intelligence-and-cti-tactical-intelligence
description: "Tactical threat intelligence. Covers low-level intelligence: indicators, tooling and malware specifics with short shelf life and direct detection value. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology."
family: threat-intelligence-and-hunting
tier: leaf
triggers: ["tactical threat intel", "ioc intelligence", "operational indicators"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [threat-intelligence-and-cti, threat-intelligence-and-cti-strategic-intelligence, cti-collection-and-enrichment, indicator-lifecycle-and-ioc-management]
parent: threat-intelligence-and-cti
---

# Threat Intelligence and CTI Tactical Intelligence - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Threat Intelligence and Hunting`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md)

## Mechanism and Preconditions

Tactical intelligence describes how an actor operates: the techniques, tooling, and infrastructure patterns that a defender can map to detections. Its output is consumed by detection engineering and hunting, so the useful form is a small set of TTP statements with the observable each produces in your telemetry, not a narrative. The main failure is abstraction - reporting 'uses Living off the Land' without naming which binary, which parent, and which command line shape.

- **CWE-778 framing:** a TTP without an observable cannot be detected, so the observable field is what makes the report tactical.
- ATT&CK v19 (April 2026) split Defense Evasion into Stealth (TA0005) and Defense Impairment (TA0112), and restructured T1562 into T1685 Disable or Modify Tools - so any TTP list older than that needs re-mapping.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the consumer is a detection engineer **THEN** deliver TTP plus observable plus log source, and stop; the rule is theirs to write.
2. **IF** the consumer is an executive **THEN** open `threat-intelligence-and-cti-strategic-intelligence`.
3. **IF** the pattern needs campaign clustering **THEN** open `diamond-model-and-campaign-clustering`.
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

1. **Extract statements, not narrative.** For each claim: the technique, the specific implementation (binary, protocol, or artifact), the observable it produces, and the log source that would contain it.
2. **Map to ATT&CK using the current tactic split.** Record technique ids with their v19 tactic placement; a technique mapped to 'defense evasion' after April 2026 is stale.
3. **Choose the branch on observable availability.** Observable present in your telemetry takes the detection-branch; observable absent takes the coverage-branch (a data source to onboard); observable unobservable in principle takes the control-branch (prevention rather than detection).
4. **Define the baseline-vs-probe differential per TTP.** Baseline: the observable's normal frequency in your estate. Probe: the shape the report describes. A TTP whose observable is ubiquitous is not detectable on its own and needs a secondary condition.
5. **State the stop condition and the proof.** Stop when every TTP has an observable, a log source, and a frequency estimate; proof is one TTP traced from report to a query you actually ran.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| TTP naming a binary, parent, and command-line shape | Proves the statement is tactical; a technique id alone is a category, not a description. |
| Observable with a measured baseline frequency | Proves detectability; a ubiquitous observable needs a secondary condition to be useful. |
| Log source the estate does not collect | Proves a coverage gap rather than a detection opportunity, and belongs in an onboarding ticket. |
| Technique mapped with the v19 tactic placement | Proves the library is current after the Defense Evasion split. |

## Worked Contrast

**Tactical report that stays at technique level:**

```text
Actor X uses:
- T1059 Command and Scripting Interpreter
- T1218 System Binary Proxy Execution
- T1547 Boot or Logon Autostart Execution
Assessment: they are sophisticated and use living off the land.
Recommendation: improve detection coverage.
```

**TTP statements with implementation, observable, and frequency:**

```text
Actor X / campaign Y  (reporting 2026-09..2026-11, two vendors)

TTP-1  T1218.011 (Stealth)  rundll32 proxy execution
  implementation: rundll32.exe with javascript: or a .dat export, spawned by excel.exe
  observable: process_creation where ParentImage endswith EXCEL.EXE and Image endswith rundll32.exe
  log source: sysmon EID 1 (collected, 100% of endpoints)
  baseline frequency: 0 across 90d in finance OU; 4/wk estate-wide (other OUs, IT macros)
  verdict: detectable with an OU-scoped condition

TTP-2  T1053.005 (Persistence)  scheduled task with a random 8-char name
  implementation: schtasks /create /tn <8 chars> /tr powershell -w hidden
  observable: 4698 where TaskName matches ^[a-z]{8}$ and TaskContent contains powershell -w hidden
  log source: windows security 4698 (collected on servers only)
  baseline frequency: 2/wk on servers (patching), 0 on workstations
  verdict: detection possible on servers; workstation coverage is a gap (ticket SEC-6733)

TTP-3  T1685 (Defense Impairment)  disable or modify tools
  implementation: reported as 'disables AV' with no artefact
  observable: none reported
  verdict: not tactical; request artefacts or treat as a prevention requirement
```

**Why this matters:** The first report lists technique ids and concludes the actor is sophisticated, which changes no detection. The second states the implementation, the observable in real field terms, the log source and whether it is collected, the measured baseline frequency, and an explicit verdict per TTP - including one TTP rejected as non-tactical because it has no artefact.

## When It Is NOT This Issue

- **Technique reported without artefacts.** It is still useful for prioritisation, but it cannot be a detection requirement until someone publishes the observable.
- **Observable that is ubiquitous in your estate.** A TTP whose only signal is a common binary needs a secondary condition; filing it as detectable produces noise.
- **Tactic label from an older ATT&CK version.** Re-map rather than filing a library bug; the tactic names changed in April 2026.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `indicator` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `threat-intelligence-and-cti-tactical-intelligence` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: threat-intelligence-and-cti-tactical-intelligence
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-200 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`osint-methodology`](../../../red-team/osint-and-red-operations/osint-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`threat-intelligence-and-cti`](../threat-intelligence-and-cti/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-intelligence-and-cti-strategic-intelligence`](../threat-intelligence-and-cti-strategic-intelligence/SKILL.md) - Threat Intelligence and Hunting (leaf)
- [`cti-collection-and-enrichment`](../cti-collection-and-enrichment/SKILL.md) - Threat Intelligence and Hunting (core)
- [`indicator-lifecycle-and-ioc-management`](../indicator-lifecycle-and-ioc-management/SKILL.md) - Threat Intelligence and Hunting (core)
- [`threat-hunting`](../threat-hunting/SKILL.md) - Threat Intelligence and Hunting (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `threat-intelligence-and-cti-tactical-intelligence` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 3 |
| Top sources | CYBER_CPT/atomic_red_team (3), CYBER_CPT/github_security_md (2), CYBER_CPT/google_threat_intel (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
