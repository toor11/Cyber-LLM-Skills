---
name: social-engineering-and-pretexting-email-and-credential-phishing
description: Email and credential phishing execution. Covers lure construction, sending infrastructure and reputation, and credential capture with MFA considerations. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: osint-and-red-operations
tier: leaf
triggers: ["phishing execution", "credential harvest", "phishing infrastructure", "evilginx"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-416]
related: [social-engineering-and-pretexting, social-engineering-and-pretexting-voice-and-message-based, osint-methodology, corporate-and-person-osint]
parent: social-engineering-and-pretexting
---


# Social Engineering and Pretexting Email and Credential Phishing - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **leaf** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Authorised email pretexting to test whether a control holds: the lure is built around a real process, the sending domain is either approved lookalike infrastructure or a sanctioned platform, and the measured outcome is whether the recipient performed the verification step the process requires. The test does not need a working credential-capture page to be valid, and capturing real credentials is out of bounds.

- **Measure the verification step, not the click.** A click is a data point; the finding is whether the recipient checked the sender through an independent channel before acting.
- **Capture nothing real.** A landing page that records entered passwords turns an authorised test into a credential incident; collect only the fact that a submission occurred.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the lure requires a lookalike domain **THEN** confirm the domain is registered to the client or the assessment team and is named in the authorisation.
2. **IF** a recipient replies with real credentials or sensitive data **THEN** stop the campaign, delete the data, and disclose immediately.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — an authorised sending domain, a recipient list, and a landing behaviour that records no secrets — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

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

- **Pinned Inputs:** An authorised sending domain or platform tenant, a recipient list, and a landing page that logs the event without capturing input values
- **First Check:** `python -c "import yaml; d=yaml.safe_load(open('phish-scope.yaml')); print(d['sending_domain'], len(d['recipients']))"`

1. Confirm the target surface: the recipient population, the process being tested, the sending domain, and the landing behaviour that records an event without secrets.
2. Choose the branch: process-verification lure when testing a specific control, awareness lure when measuring reporting rate, and reply-based lure only when the authorisation explicitly covers mailbox interaction.
3. Define the differential: compare the recipient's action against the documented process — the differential is a step taken that the process forbids, or a verification step skipped.
4. Name the stop condition: a report from a recipient, a help-desk escalation, or any real secret submitted; each halts the campaign for that cohort.
5. Prove it: the event log records recipient, timestamp, action, and the process step tested, with no captured input values, and the debrief covers everyone who acted.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Sending domain named in the authorisation` | The only defensible basis for using lookalike infrastructure; an unlisted domain is impersonation. |
| `Landing event without captured values` | Records that a submission happened while ensuring no credential is collected. |
| `Documented verification step as baseline` | Makes the result a control measurement rather than a susceptibility score. |
| `Per-cohort stop condition` | Limits harm: one report or one real secret halts that cohort immediately. |

## Worked Contrast

**Campaign That Captures Passwords and Scores Clicks:**

```text
Send a lure to all staff with a cloned login page.
Record every username and password submitted; report a 22% credential capture rate.
# BUG: real credentials captured, no process baseline, no stop condition, no debrief
```

**Process Measurement Without Secret Capture:**

```text
Cohort: accounts-payable (n=40), authorised sending domain mail-audit.client.example.
Baseline process: any payment-detail change requires a callback to the vendor's number on file.
Lure: vendor bank-detail change request.
Landing: records only that the form was opened and submitted (no field values stored).
Outcome: 6 recipients replied with new bank details without a callback -> process step skipped.
Stop: campaign halted on the first help-desk report; those recipients debriefed.
```

**Why this matters:** Capturing passwords creates a credential incident and produces a number that says nothing about which control failed. Measuring whether the callback step was performed yields an actionable finding about the process, and recording only the submission event keeps the exercise inside the authorisation.

## When It Is NOT This Issue

- **Recipient reported the email.** A report is the control working; it belongs in the results as a success, not as a failure to be re-tested.
- **Click without action.** Opening a link is not a process breach; the finding requires the process step to have been skipped.
- **Lure that would fail in reality.** A pretext that no real process would produce tests nothing; check the scenario against the documented workflow first.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `social-engineering-and-pretexting-email-and-credential-phishing` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `social-engineering-and-pretexting-email-and-credential-phishing` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: social-engineering-and-pretexting-email-and-credential-phishing
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting-voice-and-message-based`](../social-engineering-and-pretexting-voice-and-message-based/SKILL.md) - OSINT and Red Operations (leaf)
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `social-engineering-and-pretexting-email-and-credential-phishing` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 8 |
| Top sources | cyber-security/CyberSec-Dataset (1), CYBER_CPT/L5/ctf_search (1), CYBER_CPT/trend_micro_research (1), CYBER_CPT/unit42 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 7 cases |
| Grounding | multi-dataset corpus-grounded |
