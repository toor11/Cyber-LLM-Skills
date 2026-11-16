---
name: red-team-operations-and-scoping
description: "Plans and runs red team operations: objectives, rules of engagement, operational security, deconfliction and reporting. Use when running a full adversary emulation rather than a pentest."
family: osint-and-red-operations
tier: core
triggers: ["red team operations", "red team scoping", "roe", "red team opsec", "adversary emulation"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, social-engineering-and-pretexting]
---


# Red Team Operations and Scoping - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

The authorisation and control layer for assessment work: rules of engagement that name the in-scope targets, the permitted techniques, the time windows, the deconfliction channel, and the escalation path for an emergency. A scope document is what converts activity from unauthorised access into an authorised test, and its precision decides whether the work is defensible.

- **Scope is a list of assets, not a description of intent.** Ranges, hostnames, and excluded systems written explicitly, because 'the corporate network' is not a scope.
- **Deconfliction is a channel and a marker.** The SOC must be able to tell assessment traffic from an intrusion; both the contact and the observable marker belong in the document.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** an asset is not enumerated in the scope **THEN** it is out of scope, and discovering it is a report item rather than an invitation.
2. **IF** a technique could cause an outage **THEN** it needs written approval with a named approver and a rollback plan before execution.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a signed authorisation, an enumerated asset list with exclusions, and a named deconfliction contact — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A written authorisation with an asset enumeration, a technique allowlist, a time window, and a deconfliction contact; versioned and signed
- **First Check:** `python -c "import yaml; d=yaml.safe_load(open('scope.yaml')); print(sorted(d['in_scope']))"`

1. Confirm the target surface: enumerate in-scope assets by address range and hostname, and enumerate exclusions separately so both are explicit.
2. Choose the branch: time-boxed window when the target is production, out-of-hours when availability risk is high, and isolated environment when the technique is disruptive.
3. Define the differential: the scope check runs before every action, and a target not in the list is a stop rather than a judgement call.
4. Name the stop condition: an emergency stop contact, a defined trigger (unexpected outage, real intrusion indicators), and a procedure to halt.
5. Prove it: every action log line carries the scope entry that authorised it, so the record demonstrates authorisation rather than asserting it.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Enumerated in-scope ranges and hostnames` | The only form of scope that can be checked mechanically before an action. |
| `Explicit exclusions list` | Prevents an in-range but out-of-scope system from being touched, which is the most common scope breach. |
| `Deconfliction contact and observable marker` | Lets the SOC distinguish the assessment from an incident without a phone call. |
| `Emergency stop trigger and contact` | Converts an unexpected outage into a controlled halt rather than a debate. |

## Worked Contrast

**Scope Described in Prose:**

```text
Scope: the client's corporate environment, excluding anything critical.
Window: next month.
# BUG: no enumerable assets, 'critical' undefined, no contact, no stop condition
```

**Enumerated Scope With Exclusions and Controls:**

```yaml
engagement: 2026-q4-external
authorised_by: security-lead@client.example
in_scope:
  ranges: ["198.51.100.0/28"]
  hostnames: ["portal.client.example", "api.client.example"]
excluded:
  ranges: ["198.51.100.10/32"]
  notes: "payment gateway, third-party operated"
window: "2026-11-20T22:00Z/2026-11-21T04:00Z"
techniques_allowed: ["T1595", "T1190"]
deconfliction:
  contact: "soc@client.example"
  marker: "source 203.0.113.0/28, user-agent audit-ci"
emergency_stop:
  trigger: "unexpected outage or real intrusion indicators"
  contact: "+00 000 000 000"
```

**Why this matters:** A prose scope cannot be checked before an action, and undefined exclusions mean every judgement call is a scope decision made under pressure. An enumerated list with a separate exclusions block, a window, an allowed technique set, and a deconfliction marker lets every action be verified against the document, and the stop trigger turns an incident into a controlled halt.

## When It Is NOT This Issue

- **Asset discovered in scope but owned by a third party.** Ownership is separate from addressing; check the exclusions and the client's control before touching it.
- **Subdomain resolving to a SaaS provider.** A name in scope that CNAMEs outside the client's control is not automatically in scope.
- **Verbal approval for an extra technique.** Approval must be in the authorisation document; a verbal agreement is not a record.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `red-team-operations-and-scoping` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `red-team-operations-and-scoping` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: red-team-operations-and-scoping
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
- [`social-engineering-and-pretexting`](../social-engineering-and-pretexting/SKILL.md) - OSINT and Red Operations (core)
- [`ctf-and-lab-methodology`](../ctf-and-lab-methodology/SKILL.md) - OSINT and Red Operations (leaf)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `red-team-operations-and-scoping` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 8 |
| Top sources | cyber-security/CyberSec-Dataset (6), CYBER_CPT/ctf_search (2), CYBER_CPT/blackhills (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
