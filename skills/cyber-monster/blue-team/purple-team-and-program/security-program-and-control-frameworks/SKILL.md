---
name: security-program-and-control-frameworks
description: "Maps security programs to control frameworks: NIST CSF, ISO 27001, CIS Controls and SOC 2, and uses them for gap assessment. Use when structuring or assessing a security program."
family: purple-team-and-program
tier: core
triggers: ["security framework", "nist csf", "iso 27001", "cis controls", "control framework"]
cwe: [CWE-693]
owasp: []
attack: []
capec: [CAPEC-116]
related: [purple-teaming-and-adversary-emulation, remediation-tracking-and-verification, control-testing-and-audit-evidence, risk-assessment-and-treatment]
---

# Security Program and Control Frameworks - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Purple Team and Program`](../README.md) | Tier: **core** | Paired Counterpart: [`red-team-operations-and-scoping`](../../../red-team/osint-and-red-operations/red-team-operations-and-scoping/SKILL.md)

## Mechanism and Preconditions

A control framework is a vocabulary for describing what the programme does and a structure for proving it. The useful artefacts are a control set mapped to the frameworks your obligations come from, and a mapping that runs in both directions - so a framework requirement can be answered with evidence and an existing control can be justified by the requirements it satisfies. NIST CSF 2.0 added the Govern function and the Organisational Profile mechanism, CIS Controls v8.1 (current in 2026, with a v9 in development but unreleased) realigned its security functions to CSF 2.0, and both are only useful if the profile is maintained.

- **CWE-693 framing:** the programme's subject is protection-mechanism effectiveness, so a control without a test is a claim rather than a control.
- CIS Controls v8.1 has 18 Controls and 153 Safeguards across IG1 (56), IG2 (130) and IG3 (all 153); the Benchmarks are separate artefacts that give product settings.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the request is to test whether a control works **THEN** open `control-testing-and-audit-evidence`.
2. **IF** the request is to answer a specific regulatory obligation **THEN** open `compliance-mapping-and-reporting`.
3. **IF** the request is the risk register rather than the control set **THEN** open `risk-assessment-and-treatment`.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **List the obligations that actually apply.** Contractual, regulatory, and internal. Each names a framework or a clause; the list is the requirement source, not the framework's full text.
2. **Build the control set against real obligations, not against a framework's table of contents.** A control exists because something requires it or because it reduces a risk you have named; anything else is inventory.
3. **Choose the branch on the mapping direction.** Requirement-to-control takes the coverage branch (is there a control answering this clause); control-to-requirement takes the justification branch (why does this control exist).
4. **Define the baseline-vs-probe differential.** Baseline: the current Organisational Profile assessment. Probe: a re-assessment after a control change. The profile only functions if it is re-scored, otherwise it is a snapshot of intent.
5. **State the stop condition and the proof.** Stop when every applicable clause maps to a control with an owner and a test method; proof is the mapping table plus one tested control as a sample.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| Requirement clause mapped to a control with an owner and a test | Proves the mapping is operable; a clause mapped to a policy document is not a control. |
| Control justified by two frameworks and one internal risk | Proves the control set is not framework-shaped duplication. |
| Organisational Profile with current and target states | Proves CSF 2.0 is used as a management instrument rather than a poster. |
| Gap in the mapping recorded as accepted risk with a date | Proves the programme distinguishes 'not applicable' from 'not done'. |

## Worked Contrast

**Framework adoption that produces a mapping spreadsheet once:**

```text
Programme status
- Adopted NIST CSF 2.0 and CIS Controls v8.1
- 94% of CIS Safeguards implemented (self-assessed)
- Mapping spreadsheet completed by the consultant in 2024
- No changes since; framework version not tracked
```

**Control set with owners, tests, and a maintained profile:**

```yaml
framework_versions: {nist_csf: "2.0", cis_controls: "8.1", cis_benchmarks_pinned: true}
profile:
  type: organizational
  current_scored: 2026-10-30
  target_scored: 2026-10-30
  next_review: 2027-04-30

controls:
  - id: CTL-014
    statement: Privileged access is just-in-time and individually attributable
    satisfies:
      - {framework: cis_controls_v8_1, safeguard: "5.4", ig: IG2}
      - {framework: nist_csf_2_0, function: PR.AA, category: "PR.AA-05"}
      - {framework: internal, risk: R-2026-07}
    owner: identity-platform
    test: {method: sample and entitlement query, frequency: quarterly, last: 2026-10-12}
    evidence: evidence/CTL-014/2026-Q4/
    gaps:
      - {description: two break-glass accounts lack alerting, risk: accepted, review: 2027-01-31}
```

**Why this matters:** The first programme has adopted frameworks and produced a percentage, but the mapping is frozen, the framework versions are untracked, and no clause is tied to a test. The second records the versions it implements, keeps a re-scored profile with a review date, and gives each control its obligations, owner, test method, and explicit gaps - which is what a requirement-to-control mapping needs to be answerable.

## When It Is NOT This Issue

- **Requirement not applicable to the organisation.** Record the justification and exclude it; scoring it as unimplemented distorts the profile.
- **Two frameworks requiring the same control.** One control satisfying both is correct, not double-counting.
- **Control implemented but not yet tested.** Report it as untested rather than implemented; the distinction is what the profile is for.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER conclude a host or tenant is 'clean' when telemetry covering `NIST CSF` was disabled, rotated out, or uncollected.**
- **NEVER write single-keyword wildcard detections without scoping logsource, process/identity context, and false-positive exclusions.**
- **NEVER recommend destructive containment (wiping disks, deleting accounts, or isolating domain controllers) before preserving volatile evidence and checking blast radius.**

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `security-program-and-control-frameworks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Defensive Analysis / Triage Output: security-program-and-control-frameworks
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
- [`control-testing-and-audit-evidence`](../control-testing-and-audit-evidence/SKILL.md) - Purple Team and Program (core)
- [`risk-assessment-and-treatment`](../risk-assessment-and-treatment/SKILL.md) - Purple Team and Program (core)
- [`compliance-mapping-and-reporting`](../compliance-mapping-and-reporting/SKILL.md) - Purple Team and Program (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `security-program-and-control-frameworks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-693`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 20 |
| Distinct dataset sources | 10 |
| Top sources | cyber-security/CyberSec-Dataset (5), OffsecCyber (3), CYBER_CPT/gh_advisories (3), CYBER_CPT/hacktricks (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 1 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
