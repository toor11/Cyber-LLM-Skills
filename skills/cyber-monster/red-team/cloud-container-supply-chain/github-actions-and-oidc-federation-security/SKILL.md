---
name: github-actions-and-oidc-federation-security
description: "Audits GitHub Actions, GitLab CI, and cloud OIDC workload federation (`sts:AssumeRoleWithWebIdentity`): overly broad `sub` claim wildcards (`repo:org/*:*`), `pull_request_target` + PR-head checkout code execution, missing `aud` (`sts.amazonaws.com`) binding, mutable action tag vs 40-char commit SHA pinning, and over-scoped `id-token: write` / `GITHUB_TOKEN` permissions. Use when reviewing CI/CD workflows and cloud OIDC trust policies."
family: cloud-container-supply-chain
tier: core
triggers: ["github actions oidc", "sub claim wildcard iam", "pull_request_target", "pin actions to sha", "gitlab oidc aws"]
cwe: [CWE-287, CWE-829]
owasp: []
attack: []
capec: []
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
corpus_sparse: true
---

# Github Actions and OIDC Federation Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

OIDC federation replaces a stored cloud credential with a token the CI platform mints per job, and the security of the whole scheme reduces to the trust policy that accepts it. AWS evaluates a web identity token against a role trust policy with `sts:AssumeRoleWithWebIdentity`; the interesting conditions are `token.actions.githubusercontent.com:aud` (which must equal `sts.amazonaws.com` for the AWS audience) and `token.actions.githubusercontent.com:sub`, whose format is `repo:<org>/<repo>:environment:<name>` or `repo:<org>/<repo>:ref:refs/heads:<branch>`. A `StringLike` with `repo:acme/*:*` accepts every repository in the organisation, including ones a contributor can create if repository creation is open. A policy missing the `aud` condition accepts a token minted for a different audience, which is the cross-service confused deputy. GitHub's own guidance is explicit that `id-token: write` only enables fetching the OIDC token and grants no resource access, which is why the permission alone is not the finding — the trust policy is. In 2025 Identity Center's trusted identity propagation adds a second, stronger model where the role is bound to a verified user through `identitystore:UserId` rather than to a repository.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the trust policy uses `StringLike` with a wildcard in the `sub` claim **THEN** the finding is the wildcard's scope; `repo:acme/*:*` accepts every repository in the org.
2. **IF** the `aud` condition is absent or `StringLike` with a wildcard **THEN** a token minted for another audience is accepted, which is the confused-deputy branch.
3. **IF** the `sub` names an `environment:` value **THEN** the environment's protection rules are the real control; check whether required reviewers are configured.
4. **IF** the workflow grants `id-token: write` at the top level **THEN** every job can mint a token; scoping it to the deploy job is the fix.
5. **IF** the question is which code runs with the token **THEN** start at [`ci-cd-and-dependency-attacks`](../ci-cd-and-dependency-attacks/SKILL.md).
6. **IF** the federation is to GCP or Azure rather than AWS **THEN** the same discipline applies with different claim names; record which provider and which condition key.
7. **IF** the trust policy pins an exact `sub` with a protected environment and the `aud` to one value **THEN** record `Verified Safe` with both conditions quoted.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the trust policy, not the workflow.** The policy is the security boundary; the workflow's permission only determines whether a token can be requested.
2. **Resolve the `sub` format.** Exact `repo:org/repo:environment:production` is strongest; `repo:org/repo:ref:refs/heads/main` binds to a branch; `repo:org/repo:*` binds to any ref, including PR branches, which is usually not intended.
3. **Check the `aud` condition.** It must be present and exact. A missing `aud` means any token this issuer mints for any audience is acceptable.
4. **Define the baseline-vs-probe differential.** Baseline: the policy as written, evaluated against the intended repository and environment. Probe: the same policy evaluated against a different repository in the same organisation, or a different ref. A match on the probe is the finding, and `simulate-principal-policy` or a lab assume attempt proves it.
5. **Name the stop condition.** Stop at the first probe subject the policy would accept beyond the intended one. Do not assume a role in a production account.
6. **State the proof.** Report the policy statement, the condition, the probe subject it accepts, and the exact `sub` and `aud` that would close it. If the policy pins both, record the negative with the statement text.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `"StringLike": {"...:sub": "repo:acme/*:*"}` | Any repository in the organisation can assume the role, including newly created ones | AWS role trust policies |
| A trust policy with only a `sub` condition | The `aud` is unchecked, so a token minted for another service is accepted | AWS OIDC trust policies |
| `"StringEquals": {"...:sub": "repo:acme/payments-api:environment:production"}` | Exact environment binding, with the environment's protection rules as the second control | AWS role trust policies |
| `id-token: write` at the workflow top level | Every job can mint a token, including jobs that run contributor code | GitHub Actions workflows |
| A federated credential subject `system:serviceaccount:prod:*` in Azure | Any service account in the namespace can assume the identity | Azure workload identity |
| A GCP pool provider with `attributeCondition: "true"` | Any token from the issuer maps to the pool | Workload Identity Federation |

## Worked Contrast

**Vulnerable: wildcard subject, no audience condition, top-level token permission**

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringLike": {"token.actions.githubusercontent.com:sub": "repo:acme/*:*"}
    }
  }
}
```

```yaml
permissions:
  id-token: write        # every job, including the PR one
  contents: read
```

**Hardened: exact environment subject, exact audience, permission on the deploy job only**

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"},
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:acme/payments-api:environment:production"
      }
    }
  }
}
```

```yaml
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production      # protection rules apply here
    permissions:
      contents: read
      id-token: write            # scoped to this job only
```

**Why this matters:** The left policy accepts a token from any repository in the organisation and does not check the audience, so a contributor who can create a repository can assume the production role, and a token minted for another service is equally acceptable. The right policy binds to one repository and one environment with an exact audience, and the permission exists only on the job that needs it, behind environment protection rules.

## When It Is NOT This Issue

- **A wildcard `sub` scoped to `repo:acme/*:environment:production` where only one repository defines that environment.** Technically broad, practically bounded; state the environment inventory.
- **`id-token: write` on a job that runs no contributor code.** The permission only enables token minting; without a reachable trust it grants nothing.
- **A `StringLike` on the `sub` with the wildcard inside the repository name for a monorepo pattern.** Still worth tightening, but the reachable set is your own repositories.
- **A trust policy with a `sts:ExternalId` rather than OIDC conditions.** That is the older pattern for a different mechanism; check whether the principal is a role or a federated provider.
- **A GCP pool with an `attributeCondition` naming a repository and ref.** That is the control, not a wildcard.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `github-actions-and-oidc-federation-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `github-actions-and-oidc-federation-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: github-actions-and-oidc-federation-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-287, CWE-829 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `github-actions-and-oidc-federation-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-287, CWE-829`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | CYBER_CPT/hacktricks_cloud (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 1 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
