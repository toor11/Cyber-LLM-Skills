---
name: ci-cd-and-dependency-attacks-pipeline-injection
description: CI/CD pipeline injection. Covers injecting into pipeline definitions, workflow expressions and build scripts to execute in a privileged CI context. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["github actions injection", "pipeline injection", "workflow expression injection"]
cwe: [CWE-1357]
owasp: []
attack: [T1195]
capec: [CAPEC-437]
related: [ci-cd-and-dependency-attacks, ci-cd-and-dependency-attacks-dependency-confusion, cloud-recon-and-enumeration, aws-attacks]
parent: ci-cd-and-dependency-attacks
---

# Ci Cd and Dependency Attacks Pipeline Injection - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Pipeline injection is the case where data becomes code. Every CI system interpolates values into a shell: GitHub Actions evaluates `${{ }}` before the shell sees the script, so `${{ github.event.pull_request.title }}` inside a `run:` block is a direct text substitution, and a title containing a backtick or `$(...)` executes. GitLab CI interpolates variables into `script:` similarly, and Jenkins evaluates Groovy in some contexts. The three shapes worth separating are: expression injection into `run:` (the workflow's own expression language), argument injection into a shell command that does not quote (the value reaches `bash -c` as separate tokens), and environment-variable injection where a value reaches a step as `env:` and a later step sources it. The precondition is always an attacker-controlled field that reaches an interpreter: PR titles, issue bodies, commit messages, branch names, and workflow inputs are all attacker-controlled in a public repository. The fix is not escaping but removal: put the value in an environment variable and reference it as `"$TITLE"` in the shell, because the expression language never parses it as code.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** `${{` appears inside a `run:` block with a field from `github.event` **THEN** that is the finding; the expression is substituted before the shell parses.
2. **IF** the value reaches an `env:` key and is referenced as `"$VAR"` in the script **THEN** the shell treats it as data, which is the control.
3. **IF** the injection point is a branch name or tag name **THEN** the attacker needs push access; rank it below a PR title, which any contributor controls.
4. **IF** the runner is self-hosted and persistent **THEN** the severity rises, because the injected command persists across jobs.
5. **IF** the question is whether a privileged context runs contributor code **THEN** start at [`ci-cd-and-dependency-attacks`](../ci-cd-and-dependency-attacks/SKILL.md).
6. **IF** the mechanism is a dependency install rather than an interpolation **THEN** switch to [`ci-cd-and-dependency-attacks-dependency-confusion`](../ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md).
7. **IF** no `${{ }}` expression reaches a `run:` or `script:` block **THEN** record `Verified Safe` with the grep command and the file list it covered.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`ci-cd-and-dependency-attacks`](../ci-cd-and-dependency-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Locate every interpolation into an interpreter.** `run:` in GitHub Actions, `script:` in GitLab CI, `sh` steps in Jenkins, and any `eval` in a pipeline script. The file set is small and the grep is decisive.
2. **Trace each expression to its source.** `github.event.*` fields that a contributor controls: `pull_request.title`, `pull_request.body`, `issue.title`, `issue.body`, `comment.body`, `head_ref`, `commits[].message`. Fields from the base repository are not attacker-controlled.
3. **Choose the branch.** Direct expression in `run:`, unquoted shell argument, or environment-variable propagation into a script that evals.
4. **Define the baseline-vs-probe differential.** Baseline: the workflow as written, with a benign value in the field. Probe: a value containing a command substitution in a lab repository, and compare whether the command's effect appears. The differential is the effect, not the string.
5. **Name the stop condition.** Stop at the first demonstrated command execution from a contributor-controlled field in a lab fork. Do not attempt it against a repository you do not own.
6. **State the proof.** Report the workflow line, the event field, the shell that consumed it, and the environment-variable rewrite. If the value only reaches an `env:` key, record the negative with the line that proves it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `run: echo "${{ github.event.pull_request.title }}"` | Expression substituted into the script before the shell parses it, so a backtick executes | GitHub Actions |
| `run: gh pr comment $PR --body ${{ github.event.issue.title }}` | Unquoted substitution plus a command that takes a body, which is the common injection sink | GitHub Actions with `gh` |
| `env: { TITLE: "${{ github.event.pull_request.title }}" }` then `run: echo "$TITLE"` | The value is data in the shell, which is the control | GitHub Actions |
| `script: - echo $CI_MERGE_REQUEST_TITLE` in GitLab with a shell runner | Variable expansion in the runner's shell, attacker-controlled from an MR | GitLab CI |
| `github.event.head_ref` in a `run:` block | A branch name is contributor-controlled on a fork and is often interpolated unquoted | GitHub Actions |
| `permissions: contents: read` on the same workflow | Narrows what the injected command can do, which is a mitigation rather than a fix | GitHub Actions |

## Worked Contrast

**Vulnerable: PR title interpolated directly into a run block**

```yaml
name: label
on: pull_request_target
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Processing: ${{ github.event.pull_request.title }}"
          gh pr edit ${{ github.event.pull_request.number }} --add-label triaged
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

**Hardened: value passed through the environment and quoted in the shell**

```yaml
name: label
on: pull_request_target
permissions:
  contents: read
  pull-requests: write
jobs:
  label:
    runs-on: ubuntu-latest
    steps:
      - env:
          TITLE: ${{ github.event.pull_request.title }}
          NUMBER: ${{ github.event.pull_request.number }}
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          echo "Processing: $TITLE"
          gh pr edit "$NUMBER" --add-label triaged
```

**Why this matters:** The left workflow substitutes the PR title into the script text, so a title containing a command substitution becomes a command on the runner with `GH_TOKEN` in scope. The right workflow passes the same value through an environment variable, so the expression language never parses it as code and the shell sees it as a quoted string, which is the only reliable fix for this class.

## When It Is NOT This Issue

- **`${{ }}` in `with:` inputs to an action that does not evaluate them as shell.** The action receives a string; only a sink that interprets it matters.
- **A field from the base repository such as `github.repository`.** Not contributor-controlled.
- **An interpolation into `env:` that is later used as `"$VAR"`.** That is the fix, not the bug.
- **A workflow that only runs on `push` to a protected branch.** The actor already has merge rights.
- **An expression in a `name:` field.** It is rendered in the UI and never executed.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ci-cd-and-dependency-attacks-pipeline-injection` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ci-cd-and-dependency-attacks-pipeline-injection` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ci-cd-and-dependency-attacks-pipeline-injection
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1357 | Mapping: T1195]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`ci-cd-and-dependency-attacks`](../ci-cd-and-dependency-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`ci-cd-and-dependency-attacks-dependency-confusion`](../ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ci-cd-and-dependency-attacks-pipeline-injection` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1357, T1195`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 4 |
| Distinct dataset sources | 4 |
| Top sources | OffsecCyber (1), CYBER_CPT/go_exploitdb (1), CYBER_CPT/osv (1), CYBER_CPT/gh_advisories (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 3 cases |
| Grounding | multi-dataset corpus-grounded |
