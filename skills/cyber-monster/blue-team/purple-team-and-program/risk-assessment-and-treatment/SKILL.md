---
name: risk-assessment-and-treatment
description: "Performs risk assessment and treatment: likelihood and impact assessment, risk register maintenance and treatment options. Use when deciding how to handle identified risk."
family: purple-team-and-program
tier: core
triggers: ["risk assessment", "risk register", "risk treatment", "risk analysis"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, remediation-tracking-and-verification, security-program-and-control-frameworks, control-testing-and-audit-evidence]
---

# Risk Assessment and Treatment - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

Risk assessment converts uncertainty into a decision: what could happen, how likely, how bad, and what the organisation chooses to do about it. The useful register entry is small and comparable - a scenario, a likelihood, an impact, an owner, a treatment, and a review date - because the register's purpose is ranking and tracking, not prose. The main failure is pseudo-quantification: five-point scales applied without a definition, so two assessors rank the same scenario differently and the register stops informing decisions.

- **CWE-693 framing:** the assessment concerns protection effectiveness, so likelihood should account for existing controls rather than describing a world without them.
- Treatment options are finite: mitigate, transfer, avoid, accept. A register entry without one of those is an observation rather than a risk.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request is to test whether a control works **THEN** open `control-testing-and-audit-evidence`; risk assessment assumes the control state it is given.
2. **IF** the scenario is a specific vulnerability **THEN** open `vulnerability-management-and-prioritization` for the exploitation evidence.
3. **IF** the output feeds a regulatory filing **THEN** open `compliance-mapping-and-reporting`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Write the scenario as a cause-event-consequence sentence.** 'An attacker uses an unpatched edge appliance to reach the order database, causing a multi-day outage and customer data exposure.' A scenario that names only a threat is not assessable.
2. **Define the scales before scoring and use them consistently.** What does a 3 in likelihood mean in events per year? What does a 4 in impact mean in money or customers? Write the anchors down; shared anchors are what make two assessments comparable.
3. **Choose the branch on the treatment decision.** Mitigate takes the control-plan branch; transfer takes the insurance-or-contract branch; avoid takes the service-change branch; accept takes the owner-and-expiry branch.
4. **Define the baseline-vs-probe differential.** Baseline: the current residual score given existing controls. Probe: the score after the proposed treatment. A treatment that does not move the score is either mispriced or unnecessary.
5. **State the stop condition and the proof.** Stop when every entry has a scenario, anchored scores, an owner, a treatment, and a review date; proof is the register row plus one worked example showing how the anchors produced the score.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Scenario stated as cause-event-consequence | Proves the entry is assessable; a threat name alone has no likelihood or impact. |
| Likelihood anchored to observed frequency | Proves the scale is calibrated; 'medium' without an anchor is not a likelihood. |
| Residual score computed after existing controls | Proves the assessment reflects reality rather than a pre-control world. |
| Treatment with an owner and an expiry | Proves acceptance is a decision rather than a default. |

## Worked Contrast

**Register entry with unanchored scores and no treatment:**

```text
Risk: ransomware
Likelihood: high (4)
Impact: high (4)
Score: 16 - critical
Owner: security team
Treatment: mitigate by improving security posture
Review: annual
```

**Scenario with anchored scales, residual score, and a treatment plan:**

```text
R-2026-11  Scenario
  An affiliate exploits an internet-facing VPN appliance without management-plane MFA, gains
  domain credentials, and deploys ransomware on file servers, causing 3-5 days of outage and
  loss of order records for the EU entity.

Scales (annual, EU entity)
  likelihood 1 = under 1% chance this year; 2 = 1-5%; 3 = 5-20%; 4 = 20-50%; 5 = above 50%
  impact     1 = under EUR 50k; 2 = 50-250k; 3 = 250k-1M; 4 = 1-5M; 5 = above 5M or regulatory action

Assessment
  inherent  : L4 (sector reporting shows this path in use) x I4 (outage plus records) = 16
  controls  : EDR on servers, offline backups (restore tested 2026-08), 9 of 41 appliances without MFA
  residual  : L3 x I3 = 9  (backups reduce outage length; MFA gap keeps likelihood elevated)

Treatment: mitigate - MFA rollout for the 9 appliances in Q1 (owner: network-security)
  transfer partially - cyber policy covers outage to EUR 2M (reviewed 2026-06)
  accept: residual 9 with review 2027-02-01, or re-score once MFA is complete
Review: 2027-02-01 or on completion of the MFA rollout, whichever is first
```

**Why this matters:** The first entry scores a threat name on unanchored scales, so the number 16 cannot be compared with any other entry and the treatment is a slogan. The second states the scenario with a mechanism, anchors both scales, computes inherent and residual scores with the existing controls named, and records a treatment combination with an owner and an expiry.

## When It Is NOT This Issue

- **Risk already mitigated to an acceptable residual.** Keep the entry but do not re-propose treatment; the finding is an unowned acceptance.
- **Duplicate of another scenario.** Merge rather than scoring twice; duplicated risks distort the ranking.
- **Scenario outside the organisation's control.** Regulatory change or supplier insolvency belongs in a different register, with a different treatment set.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `likelihood` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `risk-assessment-and-treatment` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: risk-assessment-and-treatment
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
- [`compliance-mapping-and-reporting`](../compliance-mapping-and-reporting/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `risk-assessment-and-treatment` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 14 |
| Distinct dataset sources | 8 |
| Top sources | CYBER_CPT/atomic_red_team (4), bug-bounty-pentest-en (3), cyber-security/CyberSec-Dataset (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
