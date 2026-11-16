---
name: compliance-mapping-and-reporting
description: "Maps technical findings to compliance obligations and produces reporting: control-to-requirement mapping, evidence alignment and regulator-facing summaries. Use when reporting security posture against standards."
family: purple-team-and-program
tier: core
triggers: ["compliance mapping", "control mapping", "regulatory reporting"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, remediation-tracking-and-verification, security-program-and-control-frameworks, control-testing-and-audit-evidence]
corpus_sparse: true
---

# Compliance Mapping and Reporting - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Compliance mapping connects a requirement in a framework or regulation to the control that satisfies it, with the evidence trail that proves it operated. The output that survives audit is a trace: clause to control to test to evidence, in both directions, so a requirement can be answered and a control can be justified. The failure mode is the decorative crosswalk - a spreadsheet produced once, mapping everything to everything, that nobody maintains when the framework version changes.

- **CWE-693 framing:** a clause is satisfied by an operating control, so the mapping must terminate in test evidence rather than in a policy document.
- Framework versions matter: NIST CSF 2.0, CIS Controls v8.1 (with v8.1.2 published March 2025), ASVS 5.0.0 (May 2025) and the SSDF 1.2 draft (December 2025) all reorganised clauses, so old references break.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request is to build the control set **THEN** open `security-program-and-control-frameworks`; this skill maps to it.
2. **IF** the request is to test the controls **THEN** open `control-testing-and-audit-evidence`.
3. **IF** the obligation is a notification duty rather than a control set **THEN** the incident response legal-notification playbook owns it.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Fix the framework versions you are reporting against.** Record edition and release date per framework; a crosswalk without versions becomes wrong silently when a framework is revised.
2. **Map each applicable clause to exactly one primary control.** Secondary controls are noted, but one primary keeps accountability clear. A clause mapped to three controls has none.
3. **Choose the branch on the evidence type.** Automated controls take the query-evidence branch; manual controls take the sample-evidence branch; policy-only clauses take the attestation branch with an approver.
4. **Define the baseline-vs-probe differential.** Baseline: the crosswalk as of the last filing. Probe: the same crosswalk after a framework revision or control change. The probe identifies which mappings broke.
5. **State the stop condition and the proof.** Stop when every applicable clause has a control, a test, and an evidence path; proof is one clause traced end to end to a piece of evidence a third party could inspect.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Clause mapped to one primary control with a test | Proves the trace terminates in evidence rather than in an intention. |
| Framework edition and release recorded | Proves the mapping can be re-validated when the framework changes. |
| Evidence path per clause for the reporting period | Proves the filing can be supported after the fact, which is what auditors sample. |
| Clause marked not applicable with a justification | Proves exclusions are decisions rather than omissions. |

## Worked Contrast

**Crosswalk produced once, mapping everything to everything:**

```text
Compliance crosswalk v1 (2024)
- CIS 8.1 Control 4 mapped to: policy, training, EDR, firewall, backups
- NIST CSF mapped to: same list
- ISO 27001 mapped to: same list
Evidence: policies stored in the shared drive
Maintained by: consultant (contract ended)
```

**Versioned mapping with one primary control and a traceable evidence path:**

```yaml
frameworks:
  cis_controls: {version: "8.1", published: 2024-06-24}
  nist_csf: {version: "2.0", published: 2024-02-26}
  asvs: {version: "5.0.0", published: 2025-05-30}
reporting_period: 2026-01-01..2026-11-14

mappings:
  - clause: {framework: cis_controls, id: "4.1", title: Secure configuration process}
    primary_control: CTL-021
    secondary: [CTL-033]
    test: {type: automated, query: baseline-conformance-report, frequency: monthly}
    evidence: evidence/CTL-021/2026-11/
    status: satisfied
  - clause: {framework: cis_controls, id: "4.7", title: Manage default accounts}
    primary_control: CTL-022
    test: {type: manual, sample: 12, method: entitlement query plus walkthrough}
    evidence: evidence/CTL-022/2026-Q4/
    status: satisfied_with_exception
    exception: {description: two appliance vendor accounts cannot be renamed, compensating: network ACL}
  - clause: {framework: asvs, id: "6.2.4", title: Password security}
    primary_control: CTL-014
    status: not_applicable
    justification: no first-party password authentication; SSO only
```

**Why this matters:** The first crosswalk maps a clause to a pile of technologies, has no versions, and its maintainer has left, so nothing can be re-validated or evidenced. The second pins editions, gives each clause one primary control with its test type and evidence path, and records exceptions and not-applicable justifications explicitly - which is what a filing can actually be built from.

## When It Is NOT This Issue

- **Clause satisfied by a platform control.** A provider's managed encryption is a valid primary control; record the provider's attestation as the evidence.
- **Clause not applicable to the entity.** Record the justification; forcing a control creates work with no risk reduction.
- **Two frameworks with equivalent clauses.** One control can satisfy both; map each clause to it rather than building parallel controls.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `control mapping` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `compliance-mapping-and-reporting` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: compliance-mapping-and-reporting
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `compliance-mapping-and-reporting` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 2 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/go_exploitdb (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 2 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
