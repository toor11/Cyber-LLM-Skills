---
name: adversary-emulation-planning
description: "Plans adversary emulation: threat selection, ATT&CK technique mapping, control validation goals and safety constraints. Use when designing a red team scenario tied to a real threat actor."
family: osint-and-red-operations
tier: core
triggers: ["adversary emulation", "threat actor emulation", "attack mapping plan", "red team scenario"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Adversary Emulation Planning - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Designing an emulation plan that tests whether defences detect a specific adversary's behaviour: select techniques from a threat actor's observed tradecraft, map them to ATT&CK, define the telemetry each should generate, and write the expected detection for every step. The plan's success criterion is detection coverage, not technique execution.

- **Every step names its expected telemetry.** A step without a named event or field cannot be scored, and an unscored emulation is a red-team exercise with no defensive output.
- **Behaviour, not tooling.** Emulate the technique's observable effects so the plan remains valid when the actor changes tools, and so the detection generalises.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the actor's tradecraft is documented **THEN** derive steps from the reporting and map each to a technique id before writing any procedure.
2. **IF** a step has no expected detection **THEN** record it as a coverage gap in advance, so the result is a gap rather than a surprise.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a named adversary with public reporting, a technique mapping, and the telemetry sources in scope — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** ATT&CK technique ids per step, expected telemetry per step, and the detection that should fire; recorded in a plan table
- **First Check:** `python -c "import stix2; print('stix2 available for ATT&CK data')"`

1. Confirm the target surface: name the adversary and its reporting, the environment in scope, and the telemetry sources that are actually collected.
2. Choose the branch: technique-driven when the goal is coverage measurement, actor-driven when the goal is a realistic sequence, and control-driven when validating a specific detection.
3. Define the differential: for each step, the expected detection is the differential; a step that generates no alert when the detection exists is a telemetry failure, and one that alerts is coverage.
4. Name the stop condition: a step count and a deconfliction window agreed with the defenders, so the emulation cannot be mistaken for a real incident.
5. Prove it: each step records the technique id, the telemetry it produced (or failed to produce), and the detection verdict, producing a coverage table rather than a narrative.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `ATT&CK technique id per step` | Makes the plan comparable with coverage frameworks and reusable across actors that share techniques. |
| `Expected event and field per step` | The scoring criterion; without it the step cannot be evaluated. |
| `Deconfliction marker per step` | Distinguishes emulation traffic from a real incident for the SOC, which is a safety requirement. |
| `Coverage verdict per step` | Turns the exercise into a measurable output the defenders can act on. |

## Worked Contrast

**Emulation Plan That Only Lists Actions:**

```text
Step 1: run discovery commands.
Step 2: attempt credential access.
Step 3: move laterally.
# BUG: no technique ids, no expected telemetry, no way to score whether anything was detected
```

**Plan With Techniques, Telemetry and Verdicts:**

```text
Step 1 | T1087 Account Discovery | expected: process creation with net user /domain | source: EDR process events | detection: rule X should fire | verdict: ___
Step 2 | T1003 OS Credential Dumping | expected: handle open to lsass with the actor's tool signature | source: EDR handle events | detection: rule Y should fire | verdict: ___
Deconfliction: all activity from 10.20.30.0/24 during the agreed window, announced to the SOC.
```

**Why this matters:** A list of actions produces a story but no measurable result, and the defenders cannot tell which of their detections were exercised. Naming the technique, the expected event, and the detection that should fire makes each step a test with a pass or fail, and the deconfliction marker keeps the SOC from treating the exercise as an incident.

## When It Is NOT This Issue

- **Step executed but no telemetry expected.** Not every technique has a source in scope; record the gap instead of scoring it as a detection failure.
- **Actor reporting that names tools only.** Tool names date quickly; derive steps from described behaviour.
- **Alert from unrelated activity during the window.** Use the deconfliction marker to attribute alerts, and re-run any step whose result is ambiguous.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `adversary-emulation-planning` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `adversary-emulation-planning` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: adversary-emulation-planning
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-200 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md) - Blue Detection/Defense Counterpart
- [`osint-methodology`](../osint-methodology/SKILL.md) - OSINT and Red Operations (core)
- [`corporate-and-person-osint`](../corporate-and-person-osint/SKILL.md) - OSINT and Red Operations (core)
- [`infrastructure-osint`](../infrastructure-osint/SKILL.md) - OSINT and Red Operations (core)
- [`red-team-operations-and-scoping`](../red-team-operations-and-scoping/SKILL.md) - OSINT and Red Operations (core)
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `adversary-emulation-planning` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 29 |
| Distinct dataset sources | 11 |
| Top sources | SecEval/attck (7), OffsecCyber (4), cyber-security/CyberSec-Dataset (4), CYBER_CPT/cloudgoat (4) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 3 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
