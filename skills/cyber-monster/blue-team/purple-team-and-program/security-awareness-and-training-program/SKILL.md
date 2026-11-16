---
name: security-awareness-and-training-program
description: "Designs security awareness programs: content tied to real threats, phishing simulation design and measuring behaviour change. Use when improving human-layer resilience."
family: purple-team-and-program
tier: leaf
triggers: ["security awareness", "phishing simulation", "training program"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-416]
related: [purple-teaming-and-adversary-emulation, remediation-tracking-and-verification, security-program-and-control-frameworks, control-testing-and-audit-evidence]
---

# Security Awareness and Training Program - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **leaf** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

Awareness programmes change behaviour or they are theatre. The measurable parts are specific: how quickly people report a suspicious message, how often they use the reporting channel voluntarily, and whether click rates fall without the programme simply becoming better at filtering. Simulation results alone are a weak metric because they measure the simulator as much as the population, so a programme needs a real-world signal alongside them.

- **CWE-693 framing:** awareness is a human control, so its effectiveness is measured by behaviour under real conditions rather than by completion rates.
- Reporting is the outcome that matters: an organisation where people report quickly contains phishing far better than one with a low click rate and no reporting.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request is to design the phishing simulation itself **THEN** keep it inside policy and legal review; this skill covers the programme measurement.
2. **IF** the finding is a business email compromise **THEN** the incident response BEC playbook owns the response.
3. **IF** the request is role-based technical training **THEN** pair it with the framework skill so the requirement is traced.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Define the behaviours the programme is meant to change.** Report suspicious mail quickly, verify payment changes out of band, use the password manager, lock the screen. Each behaviour needs a measurement source that is not the training platform.
2. **Establish a baseline from real signals.** Median time-to-report for genuine phishing, voluntary report volume, helpdesk tickets for suspected fraud, and click rate from simulations. Record the measurement method with the number.
3. **Choose the branch on the behaviour gap.** Reporting gap takes the friction-reduction branch (one-click reporting, visible feedback); verification gap takes the process-control branch; knowledge gap takes the targeted-content branch.
4. **Define the baseline-vs-probe differential.** Baseline: the behaviour metric before the intervention. Probe: the same metric after, measured the same way. A change in simulation difficulty is not an improvement.
5. **State the stop condition and the proof.** Stop when each target behaviour has a pre and post measurement with the method held constant; proof is the time-to-report distribution, not the completion percentage.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Median time-to-report measured from genuine phishing reports | Proves a real-world behaviour signal; simulation click rates measure the simulator as much as the population. |
| One-click reporting with visible triage feedback | Proves friction was removed and reporting is reinforced, which is the usual cause of volume increases. |
| Simulation difficulty held constant across periods | Proves the trend is comparable; a harder simulation can make a better programme look worse. |
| Payment-change verification measured from helpdesk tickets | Proves a process behaviour rather than a knowledge score. |

## Worked Contrast

**Programme measured by completion and click rate:**

```text
Awareness programme FY26
- 96% training completion
- phishing click rate 7.2% (down from 11.4%)
- 3 simulations run, difficulty increased each time
- no reporting metric collected
Conclusion: programme is effective, continue current approach
```

**Programme measured on reporting behaviour with a constant method:**

```text
Target behaviours
  B1 report suspicious mail within 30 min of reading
  B2 verify payment-change requests out of band
  B3 use the password manager for work credentials

Baseline (2026-Q1, method fixed for the year)
  B1 median time-to-report (genuine reports, n=41): 3h 12m
     voluntary reports per 1,000 users per month: 2.1
  B2 helpdesk "verify payment change" tickets per month: 6 (process followed)
  B3 password manager active users: 61% of licensed

Interventions
  Q2 one-click report button in mail client plus auto-reply with triage outcome
  Q3 payment-change workflow requires callback confirmation in the ERP
  Q4 targeted content for the 39% not using the password manager

Probe (2026-Q4, same method, simulation difficulty held at Q1 level)
  B1 median time-to-report: 38m; voluntary reports: 5.4 per 1,000
  B2 tickets: 19 per month (process now enforced by the ERP, not by memory)
  B3 active users: 84%
Simulation click rate: 6.9% (reported for completeness, not as the primary metric)
```

**Why this matters:** The first programme reports a click rate that improved while the simulation got harder each time, collects no reporting metric, and concludes effectiveness from incomparable numbers. The second names behaviours, measures them from real signals with a fixed method, and attributes improvement to interventions - including moving a behaviour into a process control where it no longer depends on memory.

## When It Is NOT This Issue

- **Click rate rising while time-to-report falls.** A population that reports more may also click more; the reporting metric is the one that predicts containment.
- **Completion rate at 100% with no behaviour change.** Completion measures the platform, not the behaviour.
- **Simulation difficulty increased between periods.** The trend is not comparable; record it as a method change.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `awareness content` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `security-awareness-and-training-program` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: security-awareness-and-training-program
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `security-awareness-and-training-program` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/pentest_partners (3), CYBER_CPT/L5/ctf_search (1), CYBER_CPT/ctf_search (1), CYBER_CPT/trend_micro_research (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
