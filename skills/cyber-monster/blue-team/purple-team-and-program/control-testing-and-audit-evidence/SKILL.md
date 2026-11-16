---
name: control-testing-and-audit-evidence
description: "Tests controls and assembles audit evidence: control design versus operating effectiveness, sampling and evidence retention. Use when preparing for or responding to an audit."
family: purple-team-and-program
tier: core
triggers: ["control testing", "audit evidence", "control effectiveness"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, remediation-tracking-and-verification, security-program-and-control-frameworks, risk-assessment-and-treatment]
---

# Control Testing and Audit Evidence - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

Control testing answers two separate questions: was the control designed to achieve the objective (design effectiveness), and did it operate throughout the period (operating effectiveness). Design testing is a walkthrough of one instance; operating effectiveness is sampling across the period, with each sample's evidence retained. The common failure is testing design once and reporting it as operating effectiveness, which is why audit findings often cite a control that 'exists' but did not run.

- **CWE-693 framing:** effectiveness is a property of the control in operation, so the evidence is a population, a sample, and a result per sample.
- Sample selection must be documented before testing; choosing samples after seeing results invalidates the conclusion.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request is to map controls to frameworks **THEN** open `security-program-and-control-frameworks`.
2. **IF** the request is to evidence a regulatory filing **THEN** open `compliance-mapping-and-reporting`.
3. **IF** the control is technical and continuous (a detection rule or a baseline) **THEN** the population can be every occurrence; automation is preferable to sampling.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **State the control objective and the population.** What the control achieves, and the set of occurrences in the period (all privileged changes, all access reviews, all patch waves). A population definition is what makes sampling defensible.
2. **Test design with one walkthrough.** Trace a single instance end to end and record whether each step executed as designed. Note where the design has a gap even if this instance passed.
3. **Choose the branch on population size and automation.** Fully automated controls take the full-population branch (query every occurrence); partially automated take the sample branch with a documented method; manual controls take the larger sample branch with corroborating evidence.
4. **Define the baseline-vs-probe differential.** Baseline: the expected result per sample if the control operated. Probe: the actual evidence per sample. A sample with no evidence is not a pass - it is an exception requiring explanation.
5. **State the stop condition and the proof.** Stop when every sample has its evidence reference and a pass/fail/exception disposition; proof is the sample list plus the evidence bundle, not the narrative summary.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Population defined as all 214 privileged changes in the period | Proves sampling is possible; without a population, the sample size is arbitrary. |
| Sample chosen before testing with a documented method | Proves the result was not selected to succeed. |
| Sample with no retained evidence treated as an exception | Proves the test measures operation rather than the control's existence. |
| Automated control tested against full population | Proves completeness where it is affordable, which is stronger than any sample. |

## Worked Contrast

**Design walkthrough reported as operating effectiveness:**

```text
Control: quarterly access reviews are performed and documented.
Test: reviewed the Q3 access review document, it is complete and signed.
Result: control operating effectively.
Sample: 1
Period covered: Q3 only (Q1, Q2 not provided)
```

**Population, sample, and per-sample evidence across the period:**

```text
Control AC-07  Quarterly access review for tier-1 systems
Objective: entitlements are reviewed and inappropriate access removed within 5 business days.
Population: 4 quarterly reviews x 12 tier-1 systems = 48 review instances (2026-01-01..2026-11-14)

Method: 100% for review existence and sign-off; 25% sample (12 instances) for removal evidence
Sample selected 2026-11-02 from the population list (before testing, seed recorded)

instance             reviewed  signed  removals identified  removed <5d  evidence
2026-Q1 app-prod-01  yes       yes     2                    2             rev/Q1/app-prod-01.pdf
2026-Q1 db-primary   yes       yes     0                    n/a           rev/Q1/db-primary.pdf
2026-Q2 app-prod-01  yes       yes     1                    1             rev/Q2/app-prod-01.pdf
2026-Q2 cache-02     yes       NO      3                    1             rev/Q2/cache-02.pdf  <- exception
...
exceptions: 1 of 12 samples (cache-02 Q2: unsigned, 2 of 3 removals late)
design gap noted: no reminder before the review deadline
conclusion: design effective, operating effectiveness PARTIAL - 1 exception, remediation tracked as REM-221
```

**Why this matters:** The first test inspects one document, covers one quarter, and concludes the control operates - which is a design observation reported as an operating result. The second defines the population, pre-selects a sample with a recorded seed, records per-instance evidence including an exception, and separates design effectiveness from operating effectiveness in the conclusion.

## When It Is NOT This Issue

- **Sample with missing evidence but a verbal confirmation.** Not a pass; record the exception and note the compensating evidence.
- **Control that changed mid-period.** Split the population at the change and test both halves; testing the whole period against the new design overstates coverage.
- **Fully automated control with no exceptions.** Test the full population and state the query; sampling adds nothing.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `design effectiveness` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `control-testing-and-audit-evidence` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: control-testing-and-audit-evidence
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
- [`risk-assessment-and-treatment`](../risk-assessment-and-treatment/SKILL.md) - Purple Team and Program (core)
- [`compliance-mapping-and-reporting`](../compliance-mapping-and-reporting/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `control-testing-and-audit-evidence` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 6 |
| Top sources | SecEval/owasp_wstg (1), CYBER_CPT/github_security_md (1), CYBER_CPT/hacktricks (1), CYBER_CPT/ctftime (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
