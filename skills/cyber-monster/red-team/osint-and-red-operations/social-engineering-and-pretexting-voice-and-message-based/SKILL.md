---
name: social-engineering-and-pretexting-voice-and-message-based
description: Voice and message based social engineering. Covers vishing, smishing and help-desk impersonation, including pretext scripts and verification bypass. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: osint-and-red-operations
tier: leaf
triggers: ["vishing", "smishing", "helpdesk impersonation", "voice phishing"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-416]
related: [social-engineering-and-pretexting, social-engineering-and-pretexting-email-and-credential-phishing, osint-methodology, corporate-and-person-osint]
parent: social-engineering-and-pretexting
---


# Social Engineering and Pretexting Voice and Message Based - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Authorised voice and messaging pretexting: a script that follows a real process, a caller identity approved in the authorisation, and a measured outcome of whether the recipient performed the verification step. Voice adds urgency and irreversibility, so the stop conditions — distress, escalation, any request for real credentials — matter more than in email.

- **The script's job is to present the process, not to pressure.** A script built on authority or urgency measures compliance with pressure rather than the control, and produces findings the client cannot remediate.
- **The call must be endable in one sentence.** A pre-agreed disclosure line lets the tester stop instantly when a stop condition fires, without breaking character mid-explanation.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target asks to call back **THEN** that is the control working; record it and end the interaction rather than redirecting to a number you control.
2. **IF** the target becomes upset or mentions authorities **THEN** use the disclosure line, end the call, and report immediately.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an approved caller identity and number, a script with a disclosure line, and a documented verification process — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A written script with a disclosure line, an approved caller identity, and a contact log recording the process step tested
- **First Check:** `python -c "import yaml; d=yaml.safe_load(open('vishing-scope.yaml')); print(d['caller_id'], d['disclosure_line'])"`

1. Confirm the target surface: the recipient population, the process under test, the approved caller identity, and the recording or monitoring rules.
2. Choose the branch: process-verification call when testing a specific control, message-based pretext where the channel is in scope, and help-desk scenario when the control is identity proofing.
3. Define the differential: the documented verification step is the baseline; the differential is whether it was performed, and a callback to the number on file counts as the control working.
4. Name the stop condition: distress, an authority report, a request that would require real credentials or money, or a target asking to escalate.
5. Prove it: the contact log records the identity presented, the process step tested, the outcome, and the debrief, with no recording unless explicitly authorised.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Approved caller identity and number` | Makes the call attributable and prevents an unapproved number appearing on a target's phone. |
| `Disclosure line in the script` | A single sentence that ends the interaction when a stop condition fires. |
| `Callback to the number on file counted as success` | The control working is a result, not a failed attempt. |
| `Contact log with process step and outcome` | Evidence for the finding and the basis for the debrief. |

## Worked Contrast

**Script Built on Urgency With No Stop Line:**

```text
Say you are from IT and the account will be locked in five minutes.
Ask for the temporary password to prevent lockout.
# BUG: pressure-based, asks for a credential, no disclosure line, no approval for the identity presented
```

**Script That Tests the Callback Control:**

```text
Identity presented: internal service desk analyst (approved in authorisation).
Process under test: password reset requires callback to the number on file.
Script: request a reset for a named account, provide no callback number, accept whichever path the agent chooses.
Success criterion: agent performs the callback -> control works.
Disclosure line: 'This is an authorised security test; you can stop and call the number on file.'
```

**Why this matters:** A pressure script asking for a password measures whether a person can be panicked, not whether the control works, and it captures a real secret. Scripting the callback test with a disclosure line keeps the exercise focused on the documented step, and treating the callback as success gives the client a finding they can act on.

## When It Is NOT This Issue

- **Agent requested a callback and the tester refused.** Refusing in character defeats the test; the callback is the control working.
- **Recipient recognised the test and said so.** Recognition is a positive result, not a reason to escalate pressure.
- **Call to an out-of-scope number reached.** A misdialled or transferred contact outside the population is an incident, not a result.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `social-engineering-and-pretexting-voice-and-message-based` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `social-engineering-and-pretexting-voice-and-message-based` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: social-engineering-and-pretexting-voice-and-message-based
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting-email-and-credential-phishing`](../social-engineering-and-pretexting-email-and-credential-phishing/SKILL.md) - OSINT and Red Operations (leaf)
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `social-engineering-and-pretexting-voice-and-message-based` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 7 |
| Top sources | OffsecCyber (3), hackerone_disclosed_reports (3), CYBER_CPT/blackhills (2), CYBER_CPT/watchtowr_labs (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
