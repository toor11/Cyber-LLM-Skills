---
name: purple-teaming-and-adversary-emulation
description: "Runs purple team exercises: selecting techniques, executing controlled emulation, validating detection and driving remediation of gaps. Use when improving detection through collaborative testing."
family: purple-team-and-program
tier: core
triggers: ["purple team", "purple teaming", "adversary emulation validation", "detection validation", "validate detection", "test our detection", "kerberoasting detection"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation-technique-selection, purple-teaming-and-adversary-emulation-execution-and-validation, remediation-tracking-and-verification, security-program-and-control-frameworks]
---

# Purple Teaming and Adversary Emulation - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

A purple-team exercise is a controlled test of whether a specific behaviour produces the telemetry and the detection you believe it does. The unit of work is the technique: a safe emulation of one behaviour, a defined expected observable, and a recorded outcome of detected, logged-but-not-detected, or absent. Its value comes from the recording - an exercise that is not measured is a demonstration - and its safety comes from the emulation being non-destructive by construction, agreed in advance, and reversible.

- **CWE-693 framing:** the subject is protection-mechanism effectiveness, so the outcome is a coverage statement per technique rather than a pass or fail.
- ATT&CK v18 (October 2025) introduced Detection Strategies and Analytics in place of Data Sources, so an expected observable should reference the analytic that exists rather than a retired data-source label.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the technique list is not yet chosen **THEN** open `purple-teaming-and-adversary-emulation-technique-selection`.
2. **IF** the technique is chosen and you need the execution and validation record **THEN** open `purple-teaming-and-adversary-emulation-execution-and-validation`.
3. **IF** the exercise is a regulatory TLPT **THEN** the framework requirements come first; TIBER-EU (January 2025 revision, aligned with DORA) mandates purple teaming and renames the White Team to Control Team.
4. **IF** the target narrows to `purple-teaming-and-adversary-emulation-technique-selection` **THEN** open [`purple-teaming-and-adversary-emulation-technique-selection`](../purple-teaming-and-adversary-emulation-technique-selection/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.
5. **IF** the target narrows to `purple-teaming-and-adversary-emulation-execution-and-validation` **THEN** open [`purple-teaming-and-adversary-emulation-execution-and-validation`](../purple-teaming-and-adversary-emulation-execution-and-validation/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `purple-teaming-and-adversary-emulation-technique-selection` | [`purple-teaming-and-adversary-emulation-technique-selection`](../purple-teaming-and-adversary-emulation-technique-selection/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `purple-teaming-and-adversary-emulation-execution-and-validation` | [`purple-teaming-and-adversary-emulation-execution-and-validation`](../purple-teaming-and-adversary-emulation-execution-and-validation/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Agree the objective, the scope, and the safety boundary in writing.** Which techniques, which hosts, what must not happen (no destructive actions, no data exfiltration, no production denial), and who can stop the exercise. The stop authority must be named and reachable.
2. **Predict the observable before emulating.** For each technique, state the event, the field values, and the analytic that should fire. A prediction recorded in advance is what turns a result into evidence.
3. **Choose the branch on the emulation's blast radius.** Read-only behavioural emulation takes the direct branch; anything with a side effect takes the isolated-environment branch; anything requiring privileged action takes the approved-window branch with the Control Team watching.
4. **Define the baseline-vs-probe differential.** Baseline: the same telemetry before the emulation, confirming the observable is absent. Probe: during and after. The difference proves the behaviour produced the signal rather than an unrelated event.
5. **State the stop condition and the proof.** Stop when every technique has an outcome (detected, logged, absent) with its evidence reference; proof is the event id or query result captured during the probe window, not the emulation log alone.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Emulation with a pre-recorded expected observable | Proves the exercise tests a hypothesis rather than producing activity. |
| Outcome recorded as logged-but-not-detected | Proves telemetry exists and analytics do not, which is the cheapest gap to close. |
| Stop authority named and reachable during the window | Proves the safety contract is operable, not just documented. |
| Re-run after the detection change using the same emulation | Proves the fix works; without a re-run the exercise produced a ticket, not a validated control. |

## Worked Contrast

**Exercise that generates activity and reports what happened:**

```text
Purple team exercise - Tuesday
Ran several techniques from the threat report across the estate.
Some alerts fired. Analysts reviewed them.
Findings: detection coverage is decent; a few gaps were noted.
Report: shared in the security channel.
```

**Exercise with pre-recorded predictions and an outcome per technique:**

```text
Exercise PT-2026-08   Window: 2026-11-10 09:00-12:00 UTC   Stop authority: SOC lead (on call)
Safety: read-only emulation only; no persistence, no lateral movement, no data access

T1218.011  rundll32 proxy execution
  prediction (recorded 2026-11-05): sysmon EID 1 where ParentImage=excel.exe and Image=rundll32.exe
                                -> analytic A-221 expected to fire high
  baseline   : 0 events in 24h for the target hosts
  probe      : 2 events at 09:41 and 09:44 on host fin-ws-014
  outcome    : DETECTED (alert 8812 at 09:41:22, 22s after event)
  evidence   : events/pt-2026-08/t1218-011.jsonl, alert ids 8812, 8813

T1053.005  scheduled task creation with random name
  prediction: security 4698 where TaskName matches ^[a-z]{8}$ -> analytic A-305 expected to fire
  baseline   : 0 in 24h on the two test servers
  probe      : 1 event at 10:02 on srv-app-02
  outcome    : LOGGED NOT DETECTED
  evidence   : 4698 captured; analytic A-305 did not fire because it filters TaskName length > 10
  action     : widen A-305, re-run scheduled 2026-11-17

T1547.001  registry run key
  prediction: sysmon EID 13 on Run key path -> no analytic exists (expected gap)
  probe      : event captured at 10:20
  outcome    : LOGGED, NO ANALYTIC (accepted gap, ticket DET-4412)
```

**Why this matters:** The first exercise has no predictions, so 'some alerts fired' cannot be attributed to the techniques, and no outcome is reusable. The second records the prediction before the window, captures a baseline, and produces three distinct outcomes with evidence references and follow-up actions - one of which is a re-run date, which is what closes the loop.

## When It Is NOT This Issue

- **Alert fired during the window from unrelated activity.** Attribute by host, time, and field values; an unattributed alert is not a detection for that technique.
- **Technique emulated outside its real precondition.** A technique requiring elevated context emulated unprivileged tests a different behaviour and produces a misleading absent.
- **Exercise run in production without a stop authority.** Not a finding about coverage; it is a safety failure and ends the run.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `technique selection` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `purple-teaming-and-adversary-emulation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: purple-teaming-and-adversary-emulation
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-693 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`purple-teaming-and-adversary-emulation-technique-selection`](../purple-teaming-and-adversary-emulation-technique-selection/SKILL.md) - Purple Team and Program (leaf)
- [`purple-teaming-and-adversary-emulation-execution-and-validation`](../purple-teaming-and-adversary-emulation-execution-and-validation/SKILL.md) - Purple Team and Program (leaf)
- [`remediation-tracking-and-verification`](../remediation-tracking-and-verification/SKILL.md) - Purple Team and Program (core)
- [`security-program-and-control-frameworks`](../security-program-and-control-frameworks/SKILL.md) - Purple Team and Program (core)
- [`control-testing-and-audit-evidence`](../control-testing-and-audit-evidence/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `purple-teaming-and-adversary-emulation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 4 |
| Top sources | cyber-security/CyberSec-Dataset (7), CYBER_CPT/blackhills (5), bugbounty-hunter-v1 (2), CYBER_CPT/L5/ctf_search (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
