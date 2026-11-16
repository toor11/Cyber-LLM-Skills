---
name: aws-attacks
description: "Assesses and exploits AWS environments: credential discovery, IAM policy weaknesses, S3 and other storage exposure, role chaining and service-specific abuse. Use when the target runs on AWS."
family: cloud-container-supply-chain
tier: flagship
triggers: ["aws attack", "aws pentest", "s3 bucket abuse", "iam privesc aws", "aws credentials"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [aws-attacks-s3-and-storage, aws-attacks-iam-and-role-chaining, aws-attacks-compute-and-metadata, cloud-recon-and-enumeration]
---

# AWS Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **flagship** | Paired Counterpart: [`cloud-incident-response`](../../../blue-team/incident-response/cloud-incident-response/SKILL.md)

## Mechanism and Preconditions

AWS attack review is an identity-graph exercise: the question is which principal can reach which resource, and whether a role chain exists that the design did not intend. The graph has three edge types that matter. Trust edges (`sts:AssumeRole` on a role with a principal and optional `sts:ExternalId`, `aws:SourceArn`, or `aws:SourceAccount` conditions) let one principal become another. Permission edges (`iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:UpdateAssumeRolePolicy`) let a principal change what another principal can do, which is the mechanism behind every published AWS privilege-escalation path. Data edges (bucket policies, KMS key policies, resource policies with a wildcard principal) let a principal read or write without any identity policy at all. The 2025 changes that alter this graph in practice are Identity Center's trusted identity propagation, which introduces `identitystore:UserId` and `identitycenter:ApplicationArn` condition keys so a role can be constrained to a verified user rather than a shared role, and the cross-Region propagation that removes the earlier single-Region limitation. Review is therefore a directed-graph reachability question over policies, and the honest output is a path with each hop's condition listed.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a principal can call `iam:PassRole` on a role that itself has broad permissions **THEN** that is a chain hop; enumerate what the target role can do before calling it escalation.
2. **IF** a trust policy names `Principal: "*"` or another account without `sts:ExternalId` **THEN** switch to [`aws-attacks-iam-and-role-chaining`](../aws-attacks-iam-and-role-chaining/SKILL.md) for the confused-deputy analysis.
3. **IF** the resource is a bucket, a queue, or a table with a resource policy **THEN** read the resource policy first; it can grant access that no identity policy mentions.
4. **IF** a workload on EC2 reaches credentials **THEN** check the IMDS version and hop limit; switch to [`aws-attacks-compute-and-metadata`](../aws-attacks-compute-and-metadata/SKILL.md).
5. **IF** the resource is object storage **THEN** switch to [`aws-attacks-s3-and-storage`](../aws-attacks-s3-and-storage/SKILL.md) for ACL and policy interaction.
6. **IF** the estate uses Identity Center **THEN** check whether roles carry `identitystore:UserId` conditions; absent them, every federated user shares one role's full surface.
7. **IF** the review is about a permission boundary or SCP **THEN** check it at the top of the chain, because a boundary on the starting principal does not constrain a role it assumes.
8. **IF** the graph has no path from an untrusted principal to a privileged action **THEN** record `Verified Safe` with the paths you checked, not just a verdict.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Target matches `aws-attacks-s3-and-storage` | [`aws-attacks-s3-and-storage`](../aws-attacks-s3-and-storage/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `aws-attacks-iam-and-role-chaining` | [`aws-attacks-iam-and-role-chaining`](../aws-attacks-iam-and-role-chaining/SKILL.md) | Dedicated variant-specific workflow |
| Target matches `aws-attacks-compute-and-metadata` | [`aws-attacks-compute-and-metadata`](../aws-attacks-compute-and-metadata/SKILL.md) | Dedicated variant-specific workflow |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Enumerate principals and their edges.** Collect identity policies, trust policies, resource policies, permission boundaries, and SCPs. A principal's effective permissions are the intersection of identity policy and boundary, then constrained by SCP; a resource policy can grant independently of both.
2. **Build the reachability graph.** Node per principal and per resource, edge per grant. Mark the edges that are conditional (`sts:ExternalId`, `aws:SourceArn`, `aws:SourceAccount`, `kms:EncryptionContext:`) because a conditional edge is not the same as an open one.
3. **Choose the branch.** Direct over-grant, chain through `iam:PassRole` or policy mutation, cross-account trust without `ExternalId`, or resource-policy bypass of identity policy.
4. **Define the baseline-vs-probe differential.** Baseline: `aws iam simulate-principal-policy` for the starting principal against the target action, which returns `allowed` or `explicitDeny`. Probe: the same simulation after the intermediate hop, using the target role's ARN. A `probe=allowed` with `baseline=denied` is the chain, and each hop's condition is the qualifier.
5. **Name the stop condition.** Stop at the first path that reaches a privileged action from a principal an attacker could plausibly hold. Do not execute the chain.
6. **State the proof.** Report each hop with its ARN, the grant that enables it, the condition present or absent, and the simulation result at each step. If every path is denied or requires a principal outside the threat model, record the negative with the simulations you ran.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `iam:PassRole` granted with `Resource: "*"` | Any role in the account can be handed to any service, which is the first hop of most published chains | IAM identity policies, CI runner roles |
| A role trust policy with `Principal: {"AWS": "arn:aws:iam::*:root"}` | Cross-account assumption from any account that knows the role name; with no `ExternalId` it is a confused-deputy path | Role trust policies |
| A bucket policy with `Principal: "*"` and `s3:GetObject` | Public read that no identity policy mentions, so IAM review alone misses it | S3 resource policies, CloudFront origins |
| `identitystore:UserId` in a role's condition block | Identity Center trusted identity propagation: the role is bound to a verified user, which is the current best practice | IAM Identity Center role assignments |
| `aws:SourceAccount` present on a service-principal grant | Confused-deputy control: the grant is scoped to one account's resource | Lambda, CloudTrail, Config service roles |
| A permission boundary on the user but not on the role it assumes | The boundary does not follow the chain, so the role's permissions apply in full | IAM users with long-lived keys |

## Worked Contrast

**Vulnerable: pass-role to a wildcard and a role trust open to any account**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "iam:PassRole", "Resource": "*"},
    {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"], "Resource": "*"}
  ]
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::*:root"},
    "Action": "sts:AssumeRole"
  }
}
```

**Hardened: pass-role scoped to named roles, trust pinned to an account and external id**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "iam:PassRole",
     "Resource": "arn:aws:iam::111122223333:role/deploy-worker",
     "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}},
    {"Effect": "Allow", "Action": ["lambda:CreateFunction", "lambda:InvokeFunction"],
     "Resource": "arn:aws:lambda:eu-west-1:111122223333:function:deploy-*"}
  ]
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::444455556666:role/ci-runner"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "customer-8f21c"},
      "ArnLike": {"aws:PrincipalArn": "arn:aws:iam::444455556666:role/ci-runner"}
    }
  }
}
```

**Why this matters:** The left pair lets any principal that can create a function hand it any role in the account, and the role itself can be assumed from any AWS account, so the two findings compose into a full chain. The right pair scopes `PassRole` to one role and one service, restricts the function namespace, and pins the trust to a single role ARN in a single account with an external id, so neither hop is available to a principal outside the intended pipeline.

## When It Is NOT This Issue

- **`iam:PassRole` granted with a condition on `iam:PassedToService` and a specific role ARN.** That is the correct shape even though the action name looks alarming.
- **A trust policy with a wildcard principal plus a `sts:ExternalId` condition.** The external id is the confused-deputy control; a wildcard principal alone is not the finding.
- **A resource policy granting to a service principal with `aws:SourceAccount`.** That is the documented pattern for service roles.
- **An administrator role with `Action: "*"`.** Administrative roles are meant to be broad; the finding would be who can assume it.
- **A wildcard in a `Deny` statement.** Denies are meant to be broad and override allows.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `aws-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `aws-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: aws-attacks
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-incident-response`](../../../blue-team/incident-response/cloud-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`aws-attacks-s3-and-storage`](../aws-attacks-s3-and-storage/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`aws-attacks-iam-and-role-chaining`](../aws-attacks-iam-and-role-chaining/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`aws-attacks-compute-and-metadata`](../aws-attacks-compute-and-metadata/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `aws-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 15 |
| Distinct dataset sources | 9 |
| Top sources | OffsecCyber (3), bugbounty-hunter-v1 (3), CYBER_CPT/cloudgoat (3), hackerone_disclosed_reports (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 1 det / 0 tools / 8 cases |
| Grounding | multi-dataset corpus-grounded |
