---
name: security-testing-in-ci-cd
description: "Adds security testing to CI/CD: SAST, dependency scanning, secret scanning, DAST placement and build gate policy. Use when instrumenting a pipeline with security checks."
family: application-security
tier: core
triggers: ["sast", "dast in ci", "dependency scan ci", "security gate pipeline"]
cwe: [CWE-20]
owasp: []
attack: []
capec: [CAPEC-116]
related: [secure-code-review, threat-modeling, secure-sdlc-and-security-requirements, secure-design-patterns]
---

# Security Testing in Ci Cd - Blue Team Sub-Skill

> **Cyber Monster** | Family: [`Application Security`](../README.md) | Tier: **core** | Paired Counterpart: [`injection-detection-methodology`](../../../red-team/web-and-application/injection-detection-methodology/SKILL.md)

## Mechanism and Preconditions

A security gate is a pipeline stage whose failure changes what ships. The engineering problem is not running scanners but keeping the signal trustworthy: enough coverage to catch the classes you care about, few enough false positives that developers do not learn to bypass the stage, and a recorded run that proves the stage can fail at all. Gates that only ever pass are worse than absent gates because they launder risk into a green badge.

- **CWE-20 framing:** most pipeline-origin defects are unvalidated inputs at a boundary — a branch name, a PR title, a workflow input, or an artefact URL that becomes a shell argument.
- Supply-chain integrity is a separate control from scanning: OWASP Top 10:2025 A03 covers build systems and distribution, and SLSA v1.1 (approved April 2025) is the provenance vocabulary for it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the pipeline builds or publishes artefacts **THEN** treat provenance and token scope as first-class gates, not only code scanning; read `dependency-and-package-risk-review` for the consumer side.
2. **IF** the gate is meant to enforce a specific coding rule **THEN** get the requirement id from `secure-sdlc-and-security-requirements` so the failure message cites something reviewable.
3. **IF** the finding is a secret committed to history **THEN** pivot to `secrets-management-and-key-custody` for rotation; deleting the commit is not remediation.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`QUERIES.md`](QUERIES.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need IR containment runbook | [`PLAYBOOK.md`](PLAYBOOK.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Inventory every stage that can fail a change.** For each, record what it reads, what it writes, and whether its failure blocks merge or only annotates. Stages that annotate are advisory and should not be counted as coverage.
2. **Check the workflow's own input handling.** Branch names, PR titles, issue bodies, and workflow inputs flow into shell steps; confirm they are passed through environment variables or argv arrays rather than interpolated into `run:` blocks.
3. **Choose the branch by signal quality.** High-precision deterministic checks (lockfile diff, secret scan on new lines, IaC policy) block; probabilistic ones (SAST rules with history of false positives) annotate with a trend metric until tuned.
4. **Define the baseline-vs-probe differential for the gate.** Baseline: the current main branch passes. Probe: a branch with a planted defect (hard-coded credential, permissive policy, vulnerable pin) must fail the same stage. Record both run ids.
5. **State the stop condition and the proof.** Stop when each blocking stage has a probe run that failed for the intended reason, and a bypass procedure that requires an accepted-risk id; proof is the two run ids and the policy file that encodes the bypass rule.

## Concrete Patterns

| Indicator / API / Artifact | Analytical Role |
|---|---|
| `run:` step interpolating `${{ github.event.pull_request.title }}` | Proves script injection is available to any PR author on GitHub Actions; the fix is an `env:` binding, not quoting. |
| `pull_request_target` with a checkout of the PR head | Proves the workflow runs untrusted code with a write token and repository secrets. |
| Scanner stage with `continue-on-error: true` | Proves the gate is advisory; the badge is green regardless of findings. |
| Artefact referenced by mutable tag instead of digest | Proves the build can consume a different image than the one that was scanned, which is the supply-chain gap OWASP A03:2025 names. |

## Worked Contrast

**Vulnerable workflow (event data interpolated into a shell step, advisory scanner):**

```yaml
on: pull_request
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Greet
        run: echo "Building ${{ github.event.pull_request.title }}"
      - name: Scan
        continue-on-error: true
        run: semgrep scan --config p/owasp-top-ten .
```

**Hardened workflow (env binding, pinned action, blocking gate on precise rules):**

```yaml
on: pull_request
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8  # v5.0.0
        with: {persist-credentials: false}
      - name: Greet
        env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: printf 'Building %s\n' "$PR_TITLE"
      - name: Scan
        run: semgrep scan --config p/owasp-top-ten --error --sarif -o semgrep.sarif
```

**Why this matters:** The first workflow hands any PR author a shell fragment and then ignores what the scanner finds. The second binds the title through the environment so the shell never parses it, pins the action to a commit, drops the write token, and lets the scan actually fail the job.

## When It Is NOT This Issue

- **Annotation stage on a repository with no merge gate by design.** Some teams run advisory scans on legacy branches deliberately; check the branch protection rule before calling it a gap.
- **Secret-scan hit in a fixture.** Test keys that match a provider's pattern are noise; add a path-scoped allowlist entry rather than weakening the rule.
- **Scanner finding in a vendored directory.** Third-party code under `vendor/` or `node_modules/` that is not built into the artefact belongs in a dependency review, not a source gate.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER flag `security-testing-in-ci-cd` based solely on surface keywords (`SAST`)** without tracing actual dataflow, ownership, rounding/bounds math, or state ordering.
- **NEVER omit safe/non-finding dispositions when reviewing mixed code** — explicitly state which bound/validated patterns are safe so developers do not break working controls.
- **NEVER propose superficial regex/denylist patches** when structural fixes (parameterized queries, explicit DTO allowlists, borrow-only slices, internal accounting, capability separation) apply.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `security-testing-in-ci-cd` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Code & Architecture Security Review: security-testing-in-ci-cd
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
- [`secure-sdlc-and-security-requirements`](../secure-sdlc-and-security-requirements/SKILL.md) - Application Security (core)
- [`secure-design-patterns`](../secure-design-patterns/SKILL.md) - Application Security (core)
- [`secrets-management-and-key-custody`](../secrets-management-and-key-custody/SKILL.md) - Application Security (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `security-testing-in-ci-cd` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-20`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 6 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/ctf_search (2), CYBER_CPT/hacktricks (1), CYBER_CPT/github_security_md (1), CYBER_CPT/nuclei_templates (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
