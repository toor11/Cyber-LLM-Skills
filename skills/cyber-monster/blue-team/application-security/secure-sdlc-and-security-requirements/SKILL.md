---
name: secure-sdlc-and-security-requirements
description: "Embeds security in the SDLC: security requirements, design gates, code review criteria and release criteria. Use when building or improving a secure development process."
family: application-security
tier: core
triggers: ["secure sdlc", "security requirements", "security gate"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-design-patterns, secrets-management-and-key-custody]
---

# Secure Sdlc and Security Requirements - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

Security requirements engineering turns a vague expectation ('the API must be safe') into a testable outcome with an owner and a verification method, then places it at the gate where it can actually fail a change. The work is choosing the smallest set of requirements that would have caught the defects this team actually ships, and binding each one to an artefact a reviewer can open: a test, a scan configuration, a policy file, or an approval record. Requirements that nobody can check are aspirations and belong in a training plan, not in a release gate.

- **CWE-20 framing:** a requirement is only real when it names the input, the boundary, and the rejection behaviour, because that is the shape a validation test can assert.
- SSDF 1.2 (NIST SP 800-218r1 initial public draft, December 2025) adds PO.6 continuous process improvement and PS.4 robust and reliable updates; both are requirements you can evidence, not slogans.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the team has no requirements at all **THEN** start from OWASP ASVS 5.0.0 Level 1 (70 requirements across 17 chapters, released 30 May 2025) and pick only the chapters the system actually touches.
2. **IF** the ask is 'which gate should block this release' **THEN** read `security-testing-in-ci-cd` for the pipeline mechanics and keep requirement authoring here.
3. **IF** the requirement concerns a design choice (trust boundary, control placement) rather than a check **THEN** route it to `secure-design-patterns` or `threat-modeling`; gates cannot enforce a diagram.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory what already exists before writing anything.** List the tests, scanners, policies, and manual approvals in the path today, and mark which requirement each one could evidence. Most teams have coverage they never cite and gaps they never notice.
2. **Write each requirement in the checkable form.** State the asset, the boundary, the expected rejection, and the artefact that proves it: 'upload endpoint rejects >10 MB and non-allowlisted types with 413/415; proof is the negative test in tests/test_upload.py'.
3. **Choose the branch by failure cost.** Requirements protecting irreversible outcomes (key custody, audit integrity, data deletion) get a blocking gate with a human owner; reversible ones (header hardening, dependency freshness) get an advisory gate with a trend metric.
4. **Define the baseline-vs-probe differential for the gate itself.** Baseline: a known-good change passes with the gate enabled. Probe: a deliberately broken change (a planted `eval`, a removed authorisation decorator) must fail it. A gate that cannot be made to fail is decoration.
5. **Name the stop condition and the proof of adoption.** Stop when every blocking requirement has a failing probe recorded in the pipeline history; proof is the probe run id plus the requirement id, not the policy document.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| ASVS requirement id attached to a test name | Proves traceability on the application stack: a reviewer can go from the standard clause to the test that would fail if it regressed. |
| Gate with a recorded deliberate-failure run | Proves the CI gate is live on that repository; a scanner configured but never observed to fail is an assumption, and OWASP Top 10:2025 A03 (Software Supply Chain Failures) is where that assumption usually breaks. |
| Requirement with no owner team | Proves an orphan control: nobody is paged when it fails, so it decays silently. Common in requirements copied from a template. |
| SSDF practice id (PO.5, PS.2, PW.7, RV.1) mapped to a pipeline stage | Proves the programme can answer an acquirer questionnaire with evidence rather than intent, which is the practical use of SP 800-218. |

## Worked Contrast

**Unverifiable requirement (a wish with a standard's name attached):**

```yaml
requirements:
  - id: SEC-014
    text: "The application must be secure against injection attacks."
    standard: OWASP-ASVS
    gate: required
    evidence:
```

**Verifiable requirement (named boundary, rejection, artefact and owner):**

```yaml
requirements:
  - id: SEC-014
    text: >-
      Every SQL statement that takes request data is parameterised; any f-string or
      string-concatenated query under app/ fails review.
    standard: OWASP-ASVS-5.0.0-1.2.4
    boundary: http_request -> postgres
    reject: build fails, no deploy
    evidence: tests/security/test_sqli.py::test_parameterised_only
    probe: "planted f-string in app/orders/repo.py must fail the gate"
    owner: payments-platform
    failure_cost: irreversible-data-exposure
```

**Why this matters:** SEC-014 as written cannot fail, so it never will. The second version names the boundary, the artefact that evidences it, the deliberate break that proves the gate works, and the team paged when it trips — which is what makes ASVS 5.0.0 requirement ids worth citing at all.

## When It Is NOT This Issue

- **Requirement already enforced by a framework default.** Quoting an ASVS clause for output encoding when the stack autoescapes every template adds noise; cite the framework control instead and reserve requirement ids for what the default does not cover.
- **Gate failure caused by a scanner's rule pack, not the code.** A blocking failure from a third-party ruleset update is a tuning task; do not reopen the requirement.
- **Requirement for a system outside the boundary.** Encryption-at-rest for a managed service that already guarantees it belongs in the vendor assessment, not in this team's gate.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `secure-sdlc-and-security-requirements` based solely on surface keywords (`security requirement`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `secure-sdlc-and-security-requirements` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: secure-sdlc-and-security-requirements
- **Summary Verdict**: [N Confirmed Vulnerabilities, M Safe / Non-Exploitable Patterns]
- **Confirmed Findings**:
  - **[Finding Title & Severity]** (`CWE-20`): [Exact lines/component, broken invariant, reachability, and concrete impact]
  - **Minimal Hardened Fix**: [Idiomatic replacement code/config preserving intended behavior]
- **Verified Safe / Non-Finding Patterns**: [Which bound, typed, or gated constructs in the input are NOT vulnerable and why]
- **Regression Test**: [Focused unit, property/fuzz, or static-rule check preventing reintroduction]
```

## Related Sub-Skills

- [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md) - Red Assessment/Mechanics Counterpart
- [`secure-code-review`](../secure-code-review/SKILL.md) - Application Security (flagship)
- [`threat-modeling`](../threat-modeling/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)
- [`security-testing-in-ci-cd`](../security-testing-in-ci-cd/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `secure-sdlc-and-security-requirements` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 11 |
| Top sources | SecEval/owasp_wstg (3), CYBER_CPT/expku (3), SecEval/apple_platform_security (2), OffsecCyber (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
