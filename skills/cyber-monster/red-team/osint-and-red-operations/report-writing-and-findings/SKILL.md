---
name: report-writing-and-findings
description: "Writes findings that get acted on: impact-first structure, reproduction steps, evidence, risk framing and remediation guidance. Use when documenting any security finding."
family: osint-and-red-operations
tier: core
triggers: ["security report", "report writing", "findings writeup", "vulnerability report"]
cwe: [CWE-200]
owasp: []
attack: []
capec: [CAPEC-116]
related: [osint-methodology, corporate-and-person-osint, infrastructure-osint, red-team-operations-and-scoping]
---


# Report Writing and Findings - Red Team Sub-Skill

> **Cyber Monster** | Family: [`OSINT and Red Operations`](../README.md) | Tier: **core** | Paired Counterpart: [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md)

## Mechanism and Preconditions

Writing an assessment finding that a developer can act on and an auditor can verify: a title naming the defect, the exact location, the broken invariant, a reproduction that does not depend on the author, the impact in the client's terms, and a remediation that names the structural change. Risk rating follows from impact and exploitability, and both must be argued rather than asserted.

- **The reproduction must be executable by a stranger.** Steps that rely on the author's environment are not a reproduction, and an unreproducible finding is usually closed as invalid.
- **Remediation names the structural change.** 'Sanitise input' is not a fix; naming the parameter binding, the authorisation check, or the internal accounting is.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the finding depends on a precondition the client does not control **THEN** state it in the impact section, because the rating changes with it.
2. **IF** the fix is a code change **THEN** show the minimal diff, so the developer sees the intended shape without reading a paragraph.
3. **IF** the user asks how to detect, hunt, or remediate this behaviour **THEN** pivot to the paired Blue skill [`osint-for-defenders`](../../../blue-team/threat-intelligence-and-hunting/osint-for-defenders/SKILL.md).
4. **IF** the input cannot establish the precondition this skill needs — a reproducible observation, the exact location, and the broken invariant named — **THEN** **STOP**, record a verified non-finding, and name the missing precondition instead of forcing a match.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

- **Pinned Inputs:** A finding template with title, location, invariant, reproduction, impact, evidence, remediation, and rating rationale
- **First Check:** `python -c "import yaml; f=yaml.safe_load(open('finding.yaml')); print(f['title'], f['rating'])"`

1. Confirm the target surface: record the component, version, and exact location (file and line, endpoint and parameter, or contract and function).
2. Choose the branch: code finding with a diff, configuration finding with the setting and its effective value, or process finding with the documented step that was not followed.
3. Define the differential: the baseline is the benign request or the documented process, and the probe is the one change that demonstrates the defect; a finding without a baseline is an assertion.
4. Name the stop condition: one reproduction that a reviewer can run without your environment, plus one piece of evidence that survives the fix being deployed.
5. Prove it: the evidence set contains the request and response, or the file and line, or the log line with a timestamp, and the reproduction states the inputs exactly.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `Title naming the defect and the location` | Lets a reader triage without opening the body; a vague title is the main reason findings are deprioritised. |
| `Broken invariant stated as a sentence` | Turns an observation into a claim that can be argued and later tested. |
| `Minimal reproduction with exact inputs` | The only form of evidence that survives a change of author. |
| `Remediation as a diff or named control` | Gives the developer a target rather than a direction. |

## Worked Contrast

**Finding Without Reproduction or Structure:**

```text
Title: Security issue in the API.
The API seems to allow access to other users' data. Severity: critical.
# BUG: no location, no reproduction, no baseline, no rating rationale, no remediation
```

**Finding With Location, Differential and Remediation:**

```text
Title: Object-level authorisation missing on GET /v2/invoices/{id}
Location: api/invoices.py:88, parameter `id`
Broken invariant: the handler loads an invoice by id without checking tenant ownership.
Baseline: GET /v2/invoices/A with tenant-A credentials -> 200, own invoice.
Probe: GET /v2/invoices/B with tenant-A credentials -> 200, tenant-B invoice body.
Impact: any authenticated tenant can read another tenant's invoices given an id.
Rating: high - authenticated, single request, direct confidentiality impact.
Remediation: filter the query by the caller's tenant id, and add a regression test asserting 404 for a foreign id.
```

**Why this matters:** The first version cannot be reproduced or verified, so it will be closed or argued about for a week. Stating the location, the broken invariant, and a baseline-versus-probe pair makes the defect demonstrable in one request, and the rating follows from the stated impact rather than from an adjective.

## When It Is NOT This Issue

- **Finding that needs the author's environment.** If a stranger cannot reproduce it, the finding is not yet written.
- **Impact asserted without a precondition.** A rating that ignores an admin-only precondition overstates severity and damages trust.
- **Remediation that is advice.** 'Validate input' does not tell the developer what to change.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `report-writing-and-findings` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `report-writing-and-findings` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: report-writing-and-findings
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `report-writing-and-findings` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-200`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 45 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (29), bug-bounty-pentest-en (13), bugbounty-hunter-v1 (2), SecEval/owasp_wstg (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 12 cases |
| Grounding | multi-dataset corpus-grounded |
