---
name: npm-pypi-and-cargo-install-hook-supply-chain
description: "Audits package manager lifecycle execution risks (`npm` `preinstall`/`postinstall`, Python `setup.py` sdist builds, Rust `build.rs` proc-macros): `--ignore-scripts` enforcement, scoped registry `.npmrc`/`pip.conf` routing, lockfile integrity hashes, and SLSA/Trusted-Publisher verification. Use when hardening developer and CI package builds."
family: cloud-container-supply-chain
tier: leaf
triggers: ["npm postinstall security", "rust build.rs audit", "pip index-url confusion", "lockfile integrity check"]
cwe: [CWE-829, CWE-494]
owasp: []
attack: []
capec: []
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
corpus_sparse: true
---

# Npm Pypi and Cargo Install Hook Supply Chain - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Package-manager install hooks are code execution by design, and that is why this class exists. npm runs `preinstall`, `install`, and `postinstall` scripts for every dependency that declares them; pip executes `setup.py` in some legacy paths; cargo runs `build.rs` at compile time; and every one of these executes with the developer's or the CI runner's credentials in scope. The 2025 Shai-Hulud campaign is the concrete demonstration: a self-replicating worm compromised more than 500 npm packages, and its payload used a `postinstall` script to read `.npmrc` tokens, GitHub personal access tokens, and AWS, GCP, and Azure credentials, then exfiltrated them and used stolen npm tokens to republish. CISA's advisory names the controls that actually bound the damage — a dependency review against lockfiles, pinning to releases published before the compromise window, rotating developer credentials, phishing-resistant MFA, and blocking the exfiltration endpoint. The review therefore has two halves: whether install scripts can run at all in this pipeline, and which credentials are in scope when they do. The second half is usually the larger finding, because a CI runner with a broad cloud role turns a compromised dependency into a compromised account.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the install runs without `--ignore-scripts` and the lockfile changed recently **THEN** the finding is the script execution path; enumerate the credentials in the runner's environment next.
2. **IF** a dependency declares a `postinstall` script **THEN** that is a legitimate finding only when the dependency does not need it; check what it does.
3. **IF** the CI runner holds a long-lived cloud credential or a repository-write token **THEN** the blast radius finding dominates; OIDC and read-only tokens bound it.
4. **IF** the package is resolved from a public registry under an internal scope **THEN** switch to [`ci-cd-and-dependency-attacks-dependency-confusion`](../ci-cd-and-dependency-attacks-dependency-confusion/SKILL.md).
5. **IF** the concern is what a committed credential allows **THEN** start at [`secrets-hunting-and-source-leak`](../secrets-hunting-and-source-leak/SKILL.md).
6. **IF** the ecosystem is npm-specifically **THEN** note that `--ignore-scripts` is the single highest-leverage setting and that it is not the default.
7. **IF** every install uses `--ignore-scripts`, the runner has only a short-lived OIDC token, and a lockfile with integrity hashes is committed **THEN** record `Verified Safe` with the three facts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Determine whether scripts can run.** The install command in the pipeline, the presence of `--ignore-scripts`, and the package manager's configuration. This decides whether the rest of the review matters for this build.
2. **Enumerate the credentials in scope.** Runner environment variables, files in the home directory (`~/.npmrc`, `~/.aws/credentials`, `~/.config/gcloud`), and any token the workflow grants. The set is usually larger than the pipeline's author believes.
3. **Choose the branch.** Script execution enabled, credential breadth, registry fallback, or lockfile integrity.
4. **Define the baseline-vs-probe differential.** Baseline: install with `--ignore-scripts` and record which lifecycle scripts would have run. Probe: install without it. The differential is the script list, which is the attack surface, and you do not need a malicious package to demonstrate it.
5. **Name the stop condition.** Stop when the runnable script list and the credential scope are both recorded. Do not install a known-malicious package.
6. **State the proof.** Report the install command, the scripts that would run, the credentials readable from the runner, and the two changes that bound it (`--ignore-scripts` plus a short-lived token). If scripts cannot run, record the negative with the command.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `npm ci` without `--ignore-scripts` | Every dependency's lifecycle scripts run with the runner's credentials | CI configuration |
| A dependency whose `package.json` declares `postinstall: "node bundle.js"` | Arbitrary code at install time, which is the 2025 campaign's mechanism | Package manifests |
| `~/.npmrc` with an automation token readable by the install process | The credential a worm republishes with, which is how it self-propagates | Runner home directory |
| `cargo build` running a dependency's `build.rs` | Compile-time code execution, the Rust equivalent of `postinstall` | Rust builds |
| `npm ci --ignore-scripts` with a committed lockfile and integrity hashes | No install-time execution and a verifiable artifact set — the control | Hardened CI |
| A cloud credential in the runner environment | The blast radius when a script does run | CI secrets, OIDC configuration |

## Worked Contrast

**Vulnerable: install with scripts enabled on a runner holding broad credentials**

```yaml
# The runner has a long-lived cloud key and a write token, and the install runs
# every dependency's lifecycle scripts.
env:
  AWS_ACCESS_KEY_ID: ${{ secrets.PROD_KEY }}
  AWS_SECRET_ACCESS_KEY: ${{ secrets.PROD_SECRET }}
  NPM_TOKEN: ${{ secrets.NPM_PUBLISH_TOKEN }}
steps:
  - uses: actions/checkout@v4
  - run: npm ci                    # runs preinstall/install/postinstall from every dep
  - run: npm test
```

**Hardened: no install scripts, read-only token, short-lived cloud identity**

```yaml
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683
      - run: npm ci --ignore-scripts --no-audit --no-fund
      - run: npm test --ignore-scripts=false --if-present tests-only   # only project scripts
        env:
          NODE_OPTIONS: "--no-deprecation"
```

```yaml
# The deploy job, and only it, takes a short-lived OIDC credential:
permissions:
  contents: read
  id-token: write
```

**Why this matters:** The left job hands every transitive dependency's install script a production cloud key and an npm publish token, which is precisely the combination the 2025 worm harvested and used to spread. The right job runs no dependency scripts, holds only a read token during the build, and gets a short-lived cloud identity in a separate job that does not install dependencies.

## When It Is NOT This Issue

- **A `postinstall` script in a package you own, pinned by hash and reviewed.** Its content is part of your supply chain.
- **`pip install` of a wheel with no `setup.py` execution.** Modern wheels do not run arbitrary code at install.
- **`cargo build` with a vendored dependency tree.** The `build.rs` files are still code, but they are pinned and reviewed.
- **A runner with a read-only token and no cloud credentials.** Script execution is still undesirable but the blast radius is nil; state it.
- **A lockfile change that adds an optional dependency.** Review the diff rather than the event.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `npm-pypi-and-cargo-install-hook-supply-chain` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `npm-pypi-and-cargo-install-hook-supply-chain` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: npm-pypi-and-cargo-install-hook-supply-chain
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-829, CWE-494 | Mapping: Domain Invariant]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `npm-pypi-and-cargo-install-hook-supply-chain` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-829, CWE-494`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
