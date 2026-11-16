---
name: social-engineering-and-pretexting
description: "Designs and executes social engineering: pretext development, channel selection, authority and urgency levers, and reporting impact. Use when human targeting is in scope."
family: osint-and-red-operations
tier: core
triggers: ["social engineering", "pretexting", "vishing", "social engineering assessment"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-416]
related: [social-engineering-and-pretexting-email-and-credential-phishing, social-engineering-and-pretexting-voice-and-message-based, osint-methodology, corporate-and-person-osint]
---


# Social Engineering and Pretexting - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Planning and reporting authorised social-engineering tests: building a pretext grounded in the target's real processes, obtaining approval for the organisations and channels involved, running the interaction with a reporting path, and treating every contact as a person who must be debriefed. The parent skill sets the authorisation and reporting frame; the two children handle email and voice.

- **Authorisation names the organisations impersonated.** Pretending to be a specific third party without written approval creates liability that the client cannot waive.
- **Every contact has a debrief.** A person who was tested must be told, or the exercise leaves distrust behind and the programme loses its consent.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the target resolves to `social-engineering-and-pretexting-email-and-credential-phishing` **THEN** switch to [`social-engineering-and-pretexting-email-and-credential-phishing`](../social-engineering-and-pretexting-email-and-credential-phishing/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
2. **IF** the target resolves to `social-engineering-and-pretexting-voice-and-message-based` **THEN** switch to [`social-engineering-and-pretexting-voice-and-message-based`](../social-engineering-and-pretexting-voice-and-message-based/SKILL.md) (1 hop) and use that variant's procedure before continuing here.
3. **IF** the pretext requires impersonating a named external party **THEN** obtain written approval for that party before any contact.
4. **IF** a target becomes distressed or reports the contact to authorities **THEN** stop, disclose, and follow the escalation path rather than continuing the scenario.
5. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
6. **IF** the input cannot establish the precondition this skill needs — written authorisation naming the channels and organisations, and a debrief list of every person contacted — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `social-engineering-and-pretexting-email-and-credential-phishing` | [`social-engineering-and-pretexting-email-and-credential-phishing`](../social-engineering-and-pretexting-email-and-credential-phishing/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `social-engineering-and-pretexting-voice-and-message-based` | [`social-engineering-and-pretexting-voice-and-message-based`](../social-engineering-and-pretexting-voice-and-message-based/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** An authorisation document naming channels, impersonated organisations, and exclusions; a contact log; and a debrief register
- **First Check:** `python -c "import yaml; d=yaml.safe_load(open('se-scope.yaml')); print(d['channels'], d['impersonated'])"`

1. Confirm the target surface: the channels in scope, the roles that may be impersonated, the people who must not be contacted, and the approval for any external party.
2. Choose the branch: email, voice, or in-person, each with its own authorisation and its own reporting path.
3. Define the differential: the baseline is the target's documented process, and the probe is the same process under a pretext; the finding is a control that failed to verify identity against the documented process.
4. Name the stop condition: a distress signal, a legal-report trigger, or a control that would require real credentials or real money movement.
5. Prove it: the contact log records the time, channel, pretext, the control tested, and the outcome; the debrief register records who was told and when.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Channel list with impersonated organisations` | The narrowest form of authorisation that can be checked before a contact. |
| `Documented process as the baseline` | Turns the test into a measurement of whether the process was followed, rather than whether a person was fooled. |
| `Contact log with time and pretext` | Evidence of what happened and the basis for the debrief obligations. |
| `Debrief register` | Closes the loop with the people tested, which is a requirement rather than a courtesy. |

## Worked Contrast

**Pretext Run Without Channel or Impersonation Approval:**

```text
Call the service desk pretending to be a new starter's manager to test verification.
Report: the desk reset the password.
# BUG: no authorisation for the impersonated role, no contact log, no debrief recorded
```

**Authorised Pretext Against a Documented Control:**

```text
Authorisation: channel=voice, roles=internal manager, impersonated_orgs=none, exclusions=finance staff.
Baseline: service desk procedure requires callback to the line manager's number on file for resets.
Probe: caller requests a reset as an internal manager without callback.
Outcome: reset performed without callback -> control not followed (documented process vs behaviour).
Contact log: timestamp, agent id, pretext, outcome. Debrief: agent and team lead informed same day.
```

**Why this matters:** The unapproved scenario creates a legal exposure the client did not accept and leaves the tested agent with no explanation. Naming the channel, the impersonated role, and the documented control makes the test a measurement: the finding is that the callback step was skipped, and the contact log plus debrief make the exercise defensible and complete.

## When It Is NOT This Issue

- **Person followed the process and was still persuaded.** If the process itself permits the outcome, the finding is the process, not the person.
- **Out-of-scope employee contacted.** A contact outside the authorised population is an incident, not a result.
- **Real credentials captured.** Any test that obtains working credentials has crossed into a different risk category and must stop.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `social-engineering-and-pretexting` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `social-engineering-and-pretexting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: social-engineering-and-pretexting
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`social-engineering-and-pretexting-email-and-credential-phishing`](../social-engineering-and-pretexting-email-and-credential-phishing/SKILL.md) - OSINT and Red Operations (leaf)
- [`social-engineering-and-pretexting-voice-and-message-based`](../social-engineering-and-pretexting-voice-and-message-based/SKILL.md) - OSINT and Red Operations (leaf)
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `social-engineering-and-pretexting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 45 |
| Distinct dataset sources | 9 |
| Top sources | bugbounty-hunter-v1 (25), OffsecCyber (7), CYBER_CPT/blackhills (6), CYBER_CPT/L5/ctf_search (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
