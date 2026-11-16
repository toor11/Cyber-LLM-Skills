---
name: purple-teaming-and-adversary-emulation-execution-and-validation
description: Purple team execution and validation. Covers running the emulation, capturing whether detection fired, and documenting both detection and telemetry outcomes. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: purple-team-and-program
tier: leaf
triggers: ["purple execution", "detection validation run", "emulation outcome"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, purple-teaming-and-adversary-emulation-technique-selection, remediation-tracking-and-verification, security-program-and-control-frameworks]
parent: purple-teaming-and-adversary-emulation
corpus_sparse: true
---

# Purple Teaming and Adversary Emulation Execution and Validation - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **leaf** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Execution and validation is the measured part of a purple-team exercise: run the emulation, capture whether the analytic fired and with what latency, and record the result against the prediction made beforehand. The distinction that matters is between logged, detected, and actioned - telemetry without an analytic is a gap, an analytic without a response is a triage problem, and both are different fixes. The record is the deliverable, because the exercise will be re-run against the same technique after the fix.

- **CWE-693 framing:** validation is about whether the control worked, so the outcome is a property of the analytic and its response, not of the emulation.
- Alert latency is a first-class result: a detection that fires an hour late does not stop the technique, so record the delta between event time and alert time.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the technique has not been selected and predicted **THEN** open `purple-teaming-and-adversary-emulation-technique-selection` first.
2. **IF** the outcome is logged-but-not-detected **THEN** the fix is a detection change, and `threat-hunting-detection-conversion` owns the rule.
3. **IF** the outcome is detected but not actioned **THEN** the finding is in the triage playbook rather than the detection.
4. **IF** the target narrows to `purple-teaming-and-adversary-emulation` **THEN** open [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) for the variant-specific evidence set, because the parent checks here stay too coarse for that profile.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Run the baseline query immediately before the emulation.** Same query, same hosts, past 24 hours. Without it, an alert during the window cannot be attributed to the technique.
2. **Execute one technique at a time, with a bounded wait between steps.** Parallel techniques produce overlapping events and make attribution guesswork. Record the precise start and stop times.
3. **Choose the branch on the outcome class.** Detected takes the latency-and-response branch; logged-only takes the analytic-gap branch; absent takes the telemetry-gap branch, which is a data-onboarding problem rather than a detection one.
4. **Define the baseline-vs-probe differential.** Baseline: zero or known count before the window. Probe: events during it. The differential is what proves the behaviour produced the signal; without it the outcome is an assertion.
5. **State the stop condition and the proof.** Stop when each technique has an outcome, a latency, an evidence reference, and an owner for any gap; proof is the captured event plus the alert record, both with timestamps.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Detected with a measured event-to-alert latency | Proves the analytic works and quantifies its speed, which decides whether it can stop the behaviour. |
| Logged but no analytic fired, with the filter reason identified | Proves a detection gap with a specific fix rather than a generic 'improve coverage'. |
| No event at all in the telemetry | Proves a data-onboarding gap; the analytic cannot be tested because the source is absent. |
| Detected but no analyst action inside the window | Proves a triage or playbook gap, which is a different owner from the detection engineer. |

## Worked Contrast

**Results recorded as a narrative of what happened:**

```text
Ran the technique on srv-app-02 around 10am.
An alert appeared shortly after and the analyst investigated.
Logged event was present. Detection seems to work.
No further action.
```

**Per-technique record with latency, evidence references, and an owner per gap:**

```text
Technique T1053.005 / test 1   host srv-app-02   emulation start 10:02:14Z  end 10:02:31Z
baseline query (09:02-10:02): 0 events for the test host
probe window (10:02-10:12):
  event  4698 at 10:02:19Z  TaskName=a1b2c3d4  (captured, ref events/pt-2026-08/t1053-005.jsonl:12)
  analytic A-305 evaluated at 10:02:21Z -> NO MATCH (filter TaskName length > 10)
  adjacent analytic A-118 fired at 10:05:40Z (alert 8901) - different technique, excluded from this result
outcome: LOGGED, NOT DETECTED
latency: n/a (no matching alert)
owner: detection-eng (rule A-305 filter change)
action: widen filter, ticket DET-4409, re-run scheduled 2026-11-17
evidence: events/pt-2026-08/t1053-005.jsonl, analytic trace A-305@10:02:21Z
```

**Why this matters:** The first record cannot be reproduced: no times, no evidence reference, no way to tell whether the alert was even for this technique. The second fixes the window, captures the baseline, records the event and the analytic evaluation with timestamps, excludes an adjacent alert from the result, and assigns the fix - which is what makes the re-run meaningful.

## When It Is NOT This Issue

- **Adjacent alert during the window for a different technique.** Attribute by field values; counting it as a detection for this technique inflates coverage.
- **Emulation that did not run because a precondition was missing.** That is an inconclusive result, not an absent detection; record it as such and re-run when the precondition exists.
- **Detection that fired from a lab or scanner host.** Confirm the source host is the emulation target; scanner traffic often matches behavioural rules.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `test run` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `purple-teaming-and-adversary-emulation-execution-and-validation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: purple-teaming-and-adversary-emulation-execution-and-validation
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-693 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) - Purple Team and Program (core)
- [`purple-teaming-and-adversary-emulation-technique-selection`](../purple-teaming-and-adversary-emulation-technique-selection/SKILL.md) - Purple Team and Program (leaf)
- [`remediation-tracking-and-verification`](../remediation-tracking-and-verification/SKILL.md) - Purple Team and Program (core)
- [`security-program-and-control-frameworks`](../security-program-and-control-frameworks/SKILL.md) - Purple Team and Program (core)
- [`control-testing-and-audit-evidence`](../control-testing-and-audit-evidence/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `purple-teaming-and-adversary-emulation-execution-and-validation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
