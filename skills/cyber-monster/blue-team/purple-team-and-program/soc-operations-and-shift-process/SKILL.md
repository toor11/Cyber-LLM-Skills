---
name: soc-operations-and-shift-process
description: "Runs SOC operations: shift handover, alert queue management, escalation criteria and documentation standards. Use when operating or improving a security operations centre."
family: purple-team-and-program
tier: core
triggers: ["soc operations", "shift handover", "alert queue", "soc process"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, remediation-tracking-and-verification, security-program-and-control-frameworks, control-testing-and-audit-evidence]
---

# SOC Operations and Shift Process - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

SOC operations is queue management under uncertainty: getting the right alert to the right analyst with enough context to decide, documenting the decision, and handing over without losing state. The measurable properties are time in queue, escalation accuracy, and the proportion of alerts closed with a recorded reason. Most SOC dysfunction is not analyst skill but queue design - alerts without context, escalation criteria that vary by shift, and handovers that drop ownership.

- **CWE-778 framing:** an alert closed without a recorded decision destroys the evidence that the process worked, which is the same problem as missing telemetry.
- Queue design determines outcomes: a single undifferentiated queue guarantees that low-value alerts consume the attention high-value ones need.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the problem is alert quality rather than process **THEN** open `alert-tuning-and-false-positive-reduction` in the detection family.
2. **IF** the request is the escalation path for a confirmed incident **THEN** the incident response triage and timeline playbook owns it.
3. **IF** the request is detection coverage measurement **THEN** open `security-metrics-and-detection-coverage`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Define the queue tiers and what enters each.** Tier 1 triage, tier 2 investigation, and a separate queue for enrichment-only items. Each tier needs entry criteria, not just a name.
2. **Standardise the decision record.** Every closure states a reason from a closed list (true positive, benign, expected activity, duplicate, insufficient data) plus the evidence. Free-text closures cannot be measured.
3. **Choose the branch on the alert's ambiguity.** Deterministic and high-fidelity takes the auto-close branch with a recorded reason; ambiguous takes the enrichment branch; suspicious takes the escalation branch with the criteria that triggered it.
4. **Define the baseline-vs-probe differential.** Baseline: median time in queue and closure-reason distribution for the prior period. Probe: the same after a process change. A change that reduces time in queue while increasing 'insufficient data' closures has moved the problem, not solved it.
5. **State the stop condition and the proof.** Stop when every queue has entry criteria, a closure-reason list, and a handover template; proof is the closure-reason distribution plus one handover that preserved ownership.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Closure without a reason from the closed list | Proves the decision record is unusable for tuning and for audit. |
| Alert entering tier 2 without the enrichment fields analysts need | Proves queue design pushes investigation work upstream, which is the main cause of backlog. |
| Handover that names an alert but not its current state | Proves ownership is lost across shifts, which is how items age silently. |
| Escalation criteria that differ by shift | Proves outcomes depend on who is working, which makes metrics incomparable. |

## Worked Contrast

**Queue managed by volume with free-text closures:**

```text
SOC queue (single)
- 1,240 alerts/day, all in one list
- analysts pick what looks urgent
- closures: "nothing found", "checked", "false alarm"
- escalation: "if it looks bad, call the lead"
- handover: verbal at shift change
```

**Tiered queue with closed-list reasons and a stateful handover:**

```text
Queues
  T1 triage    : all detections; entry = any rule firing
  T2 investigate: entry = T1 marks suspected TP OR alert has an external indicator match
  ENRICH       : entry = alert needs an asset/identity join before triage; auto-closes on enrichment
  Criteria published in the runbook, same for every shift.

Closure reasons (closed list)
  true_positive | benign_expected | benign_unexpected | duplicate | insufficient_data | policy_exception

Daily snapshot 2026-11-13
  T1 in: 1,180  out: 1,166  median time in queue: 22m   p90: 1h 40m
  T2 in: 84     out: 79     median: 3h 10m
  closure mix: benign_expected 61%, true_positive 6%, duplicate 18%, insufficient_data 12%, other 3%
  insufficient_data alerts: 141, top source = EDR rule 4412 (missing asset owner) -> tuning ticket TUN-881

Handover 06:00 -> 14:00
  item: alert 90211 on host fin-ws-014
  state: T2 investigation, process tree captured, awaiting identity owner confirmation
  owner: a.novak (continues) ; escalation path: soc-lead if no response by 10:00
  next action: query IdP for the account's recent MFA events
```

**Why this matters:** The first queue has no entry criteria, no measurable closure reasons, and a verbal handover, so time in queue and accuracy cannot be improved. The second defines tiers with entry criteria, a closed reason list, a daily distribution that identifies the alert source causing insufficient-data closures, and a handover that states the item's current state and next action.

## When It Is NOT This Issue

- **High insufficient-data rate caused by a missing log source.** That is a telemetry ticket, not a process failure; the queue is correctly flagging it.
- **Duplicate closures rising after a rule change.** That is a tuning success, not a quality problem.
- **Escalation by a junior analyst outside criteria.** Review the criteria; a consistent pattern of out-of-criteria escalations means the criteria are wrong.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `handover` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `soc-operations-and-shift-process` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: soc-operations-and-shift-process
- **Verdict & Confidence**: [Confirmed Malicious | Benign Baseline | Control Gap | Inconclusive - Telemetry Missing] (Confidence: High/Medium/Low)
- **Telemetry & Evidence Checked**: [Exact log sources, artifacts, UTC window, and uncollected gaps]
- **Behavioral Analysis**: [Observed signal vs expected baseline; Taxonomy: CWE-693 / Domain Invariant]
- **Pivot & Substitute Artifacts**: [Secondary host/network/identity evidence checked when primary logs are absent]
- **Containment / Detection / Hardening Action**: [Concrete query, config diff, or sequenced response step]
```

## Related Sub-Skills

- [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`purple-teaming-and-adversary-emulation`](../purple-teaming-and-adversary-emulation/SKILL.md) - Purple Team and Program (core)
- [`remediation-tracking-and-verification`](../remediation-tracking-and-verification/SKILL.md) - Purple Team and Program (core)
- [`security-program-and-control-frameworks`](../security-program-and-control-frameworks/SKILL.md) - Purple Team and Program (core)
- [`control-testing-and-audit-evidence`](../control-testing-and-audit-evidence/SKILL.md) - Purple Team and Program (core)
- [`risk-assessment-and-treatment`](../risk-assessment-and-treatment/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `soc-operations-and-shift-process` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/kali_tools_zh (2), CYBER_CPT/ctf_search (1), CYBER_CPT/awesome_list (1), CYBER_CPT/sqlmap_wiki (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
