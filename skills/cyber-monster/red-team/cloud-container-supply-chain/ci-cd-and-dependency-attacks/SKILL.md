---
name: ci-cd-and-dependency-attacks
description: "Exploits CI/CD and dependency trust: pipeline injection, secret exposure in build logs, dependency confusion, and artifact tampering. Use when the build system or package ecosystem is in scope."
family: cloud-container-supply-chain
tier: core
triggers: ["ci cd attack", "pipeline injection", "dependency confusion", "github actions exploit", "artifact tampering"]
cwe: [CWE-1357]
owasp: []
attack: [T1195]
capec: [CAPEC-437]
related: [ci-cd-and-dependency-attacks-pipeline-injection, ci-cd-and-dependency-attacks-dependency-confusion, cloud-recon-and-enumeration, aws-attacks]
---

# Ci Cd and Dependency Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

CI/CD attack review is about which code the pipeline executes and with what authority. Three surfaces dominate. Pipeline definition trust: a workflow file that runs on `pull_request_target`, a GitLab `include: remote`, a Jenkinsfile read from the repository, or a build script fetched over the network all let a contributor's code run with the pipeline's credentials. Expression injection: `${{ github.event.issue.title }}` and its equivalents interpolate attacker-controlled strings into a shell, so a title containing `$(curl ...)` executes on the runner. Dependency resolution: an install step that resolves a name from a public registry before checking an internal one, or that installs without a lockfile, runs whatever the registry returns — the mechanism behind the 2025 Shai-Hulud npm worm, which compromised over 500 packages, harvested GitHub PATs and cloud credentials, and republished itself through stolen npm tokens. CISA's advisory on that campaign names the controls that actually work: pin to releases published before the compromise window, rotate developer credentials, mandate phishing-resistant MFA, and block the exfiltration endpoint. The review question is the same in all three: what authority does the pipeline hold, and can a contributor reach it.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the pipeline runs on a pull-request event and checks out the PR head **THEN** the finding is the combination; either alone is not the same severity.
2. **IF** a workflow interpolates an event field into `run:` **THEN** switch to [`ci-cd-and-dependency-attacks-pipeline-injection`](../ci-cd-and-dependency-attacks-pipeline-injection/SKILL.md).
3. **IF** a dependency resolves from a public registry under an internal name **THEN** switch to [`ci-cd-and-dependency-attacks-dependency-confusion`](../ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md).
4. **IF** the pipeline holds long-lived cloud credentials for a deploy step **THEN** the finding is the credential model; OIDC federation is the replacement.
5. **IF** a third-party action is referenced by a tag rather than a commit SHA **THEN** the finding is mutability, and the 2025 action compromises are the argument.
6. **IF** the question is the OIDC trust policy rather than the workflow **THEN** switch to [`github-actions-and-oidc-federation-security`](../github-actions-and-oidc-federation-security/SKILL.md).
7. **IF** the pipeline runs no untrusted code and holds only read-only tokens **THEN** record `Verified Safe` with the permission block and the trigger.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `ci-cd-and-dependency-attacks-pipeline-injection` | [`ci-cd-and-dependency-attacks-pipeline-injection`](../ci-cd-and-dependency-attacks-pipeline-injection/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `ci-cd-and-dependency-attacks-dependency-confusion` | [`ci-cd-and-dependency-attacks-dependency-confusion`](../ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Determine the trigger and the trust level it implies.** `pull_request` from a fork runs with a read-only token and no secrets; `pull_request_target` runs in the base repository's context with secrets. The trigger is the first fact because it decides everything downstream.
2. **Enumerate the pipeline's authority.** Token permissions, available secrets, cloud credentials, and whether the runner is self-hosted and persistent.
3. **Choose the branch.** Untrusted code with pipeline authority, expression injection, dependency resolution, or credential model.
4. **Define the baseline-vs-probe differential.** Baseline: the pipeline's declared `permissions` block and the secrets it can read, as the platform reports them. Probe: the same pipeline on a fork PR, which shows what a contributor can actually reach. The differential is a permission present in the probe and absent from the design.
5. **Name the stop condition.** Stop at the first contributor-reachable step that holds a token or secret with write authority. Do not push a workflow to a real repository.
6. **State the proof.** Report the trigger, the checkout ref, the permissions block, the secret or credential reached, and the minimal change (split the workflow, pin the SHA, use OIDC). If the fork path holds no authority, record the negative with the permission block.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `on: pull_request_target` with `actions/checkout` of `head.sha` | Contributor code runs with base-repository secrets and a write token | GitHub Actions workflows |
| No top-level `permissions:` block | The token gets the repository default, which is often write | GitHub Actions, organisation settings |
| `uses: some/action@v3` | A mutable tag, so the code that runs can change without a review | Any workflow using third-party actions |
| A long-lived cloud access key in repository secrets | A credential that survives the pipeline and is readable by any step | Deploy workflows, Jenkins credentials |
| `id-token: write` only on the deploy job | Correct scope: OIDC federation with the token minted where it is needed | Modern GitHub Actions |
| A self-hosted runner with a persistent workspace | State from one job is readable by the next, so a fork PR can plant code | Runner configuration |

## Worked Contrast

**Vulnerable: pull_request_target checking out the fork head, with a write token and long-lived keys**

```yaml
name: pr-check
on: pull_request_target
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}   # fork code
      - run: npm ci && npm test                            # runs fork scripts
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.PROD_AWS_KEY }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.PROD_AWS_SECRET }}
```

**Hardened: unprivileged PR job, SHA-pinned actions, OIDC on an isolated deploy job**

```yaml
name: ci
on: pull_request
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: npm ci --ignore-scripts && npm test
---
name: deploy
on:
  push:
    branches: [main]
permissions:
  contents: read
  id-token: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - uses: aws-actions/configure-aws-credentials@e3dd6a429d7300a6a4c196c26e071d42e034513
        with:
          role-to-assume: arn:aws:iam::111122223333:role/deploy
          aws-region: eu-west-1
```

**Why this matters:** The left workflow hands fork-controlled code the production access key and a write token, so a single pull request is enough to read every secret the pipeline can see. The right pair splits the trust levels: the PR job has a read-only token and runs no install scripts, and the deploy job exists only on a push to main, takes a short-lived OIDC credential, and pins its actions to commit SHAs.

## When It Is NOT This Issue

- **`pull_request_target` used only to comment on a PR, with no checkout of the head ref.** The privileged context never runs contributor code.
- **A default `permissions:` block at the organisation level set to read-only, with no per-workflow override.** The effective token is read-only; cite the organisation setting.
- **A third-party action pinned by tag inside an internal, mirrored registry.** The mirror is the control; state it.
- **Long-lived credentials in a repository that only maintainers can push to, with no fork PR path.** The credential model is still worth changing, but the contributor-reachable argument does not hold.
- **`npm ci` without `--ignore-scripts` in a repository with a committed lockfile and a private registry proxy.** The proxy and the lock are the controls.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `ci-cd-and-dependency-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `ci-cd-and-dependency-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: ci-cd-and-dependency-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1357 | Mapping: T1195]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`ci-cd-and-dependency-attacks-pipeline-injection`](../ci-cd-and-dependency-attacks-pipeline-injection/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`ci-cd-and-dependency-attacks-dependency-confusion`](../ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `ci-cd-and-dependency-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1357, T1195`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 16 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (4), bugbounty-hunter-v1 (3), CYBER_CPT/hacktricks (2), CYBER_CPT/osv (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 9 cases |
| Grounding | multi-dataset corpus-grounded |
