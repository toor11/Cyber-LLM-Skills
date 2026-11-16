---
name: aws-attacks-compute-and-metadata
description: AWS compute and metadata exploitation. Covers EC2 and container credential theft through IMDS, user data exposure and instance profile abuse. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["ec2 metadata", "imdsv1", "user data exposure", "instance profile"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [aws-attacks, aws-attacks-s3-and-storage, aws-attacks-iam-and-role-chaining, cloud-recon-and-enumeration]
parent: aws-attacks
---

# AWS Attacks Compute and Metadata - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-incident-response`](../../../blue-team/incident-response/cloud-incident-response/SKILL.md)

## Mechanism and Preconditions

Compute-side AWS findings come from credentials that reach a workload the operator does not fully control. The instance metadata service is the classic: IMDSv1 answers a plain `GET http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` with temporary credentials, so any server-side request forgery, any proxy misconfiguration, or any process on the host can obtain the instance role. IMDSv2 requires a `PUT` to `/latest/api/token` with a `X-aws-ec2-metadata-token-ttl-seconds` header and then sends the token, which raises the bar against naive SSRF but not against a full-request SSRF or a process on the host. The second source is user data: `curl http://169.254.169.254/latest/user-data` returns whatever the launcher put there, which is where secrets end up when someone passes them as a startup script. The third is the container and function surface: a Lambda function's environment variables are readable by anything that can call `lambda:GetFunctionConfiguration`, and an ECS task's credential endpoint is reachable from any process in the task. The precondition is a network path to the metadata endpoint or an API call with the right permission, and the review question is which of those paths exists from an untrusted position.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the instance metadata service is reachable with a plain `GET` **THEN** IMDSv1 is enabled, which is the finding; the proof is one request, not a full SSRF chain.
2. **IF** `HttpTokens` is `optional` rather than `required` **THEN** IMDSv2 is not enforced, which is the same exposure with a different name.
3. **IF** `HttpPutResponseHopLimit` is above 1 **THEN** containers can reach the metadata service through the host; the default of 1 blocks the common container path.
4. **IF** user data contains a secret **THEN** any process that can reach the metadata endpoint reads it, and the finding is the secret's placement, not SSRF.
5. **IF** the workload is a container or function **THEN** check the task credential endpoint or the environment variables respectively; the metadata service may not be the path.
6. **IF** the target is an IAM policy question **THEN** start at [`aws-attacks`](../aws-attacks/SKILL.md) and return here only for the credential-delivery path.
7. **IF** the review finds no network path from an untrusted position to the endpoint **THEN** record `Verified Safe` with the hop limit and token requirement you read.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`aws-attacks`](../aws-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Determine which metadata paths exist.** IMDSv1 versus v2 enforcement, the PUT hop limit, and whether the workload is on EC2, ECS, EKS, or Lambda. Each has a different credential endpoint.
2. **Check the credential delivery, not just the endpoint.** Whether the role is attached to the instance or to the task, whether the credentials are in an environment variable or fetched, and whether the process that fetches them runs as a low-privilege user.
3. **Choose the branch.** IMDSv1 reachable, hop limit too high, user-data secret, Lambda environment exposure, or task credential endpoint reachable from a sibling container.
4. **Define the baseline-vs-probe differential.** Baseline: a `GET` to the metadata endpoint from the instance itself, which succeeds and is expected. Probe: the same request from a container, from a workload with a narrower role, or through an application's fetch primitive. Success from a position that should not have credentials is the finding.
5. **Name the stop condition.** Stop at the first credential response obtained from a position outside the trusted set. Do not use the credential, and do not attempt to escalate with it.
6. **State the proof.** Report the endpoint version, the hop limit, the position the request came from, and the role's permissions as read from IAM. If the endpoint requires a token and the hop limit is 1, record the control that closed it.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `curl` to `169.254.169.254/latest/meta-data/iam/security-credentials/` returning JSON | IMDSv1 is enabled, so any path to the endpoint yields credentials | EC2 instances, launch templates |
| `HttpTokens: optional` in instance metadata options | v2 is offered but not required, which is the same exposure | EC2 `modify-instance-metadata-options` |
| `HttpPutResponseHopLimit: 2` or higher | Containers reach the metadata service through the host, which is the common lateral path | EKS and ECS hosts |
| Secrets in `user-data` | Any reader of the metadata endpoint gets them, and so does anyone with `ec2:DescribeInstanceAttribute` | Launch scripts, Terraform user-data |
| `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` present in a shared task namespace | Task-role credentials reachable from a sibling container in the same task | ECS task definitions |
| IMDSv2 token required with hop limit 1 and no secrets in user data | The credential path is closed; the control to cite | Hardened EC2 and EKS hosts |

## Worked Contrast

**Vulnerable: metadata options that allow v1 and container transit, with secrets in user data**

```hcl
# IMDSv1 still answers, and a hop limit of 2 lets containers reach it through the
# host. The launch template also puts a database password in user-data.
resource "aws_launch_template" "app" {
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"     # v1 allowed
    http_put_response_hop_limit = 2              # containers can reach it
  }
  user_data = base64encode(<<-EOT
    #!/bin/bash
    export DB_PASSWORD="hunter2-prod"             # readable via /latest/user-data
    EOT
  )
}
```

**Hardened: v2 enforced, hop limit 1, no secrets in user data, credentials via a role only**

```hcl
# v2 required means a plain GET returns 401, and hop limit 1 stops container
# transit. User data carries no secrets; the database credential comes from
# Secrets Manager at runtime using the instance role.
resource "aws_launch_template" "app" {
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
  user_data = base64encode(<<-EOT
    #!/bin/bash
    aws secretsmanager get-secret-value --secret-id prod/db --query SecretString \
      --output text > /run/db-secret
    chmod 0400 /run/db-secret
    EOT
  )
}
```

**Why this matters:** The left template gives any SSRF, any container, and any process with `ec2:DescribeInstanceAttribute` a path to both the instance credentials and a plaintext database password. The right template forces a token so a blind GET fails, blocks container transit with a hop limit of 1, and fetches the secret at runtime through the role so the metadata service holds no secret of its own.

## When It Is NOT This Issue

- **IMDSv2 required with a hop limit of 1 on an EC2 instance.** The endpoint still answers to the instance itself, which is expected; there is no finding without a path from outside.
- **A container reaching the metadata service with hop limit 1.** The request does not traverse the extra hop, so v2 token requests from containers fail; measure rather than assume.
- **User data that references a parameter path rather than a value.** `ssm get-parameter` in a script is not a secret in user data.
- **A Lambda environment variable holding a non-secret such as a table name.** Environment exposure matters only for secret values.
- **A role attached to an instance with read-only permissions on public data.** Credential exposure without consequence; report the path but not a severity.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `aws-attacks-compute-and-metadata` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `aws-attacks-compute-and-metadata` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: aws-attacks-compute-and-metadata
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-incident-response`](../../../blue-team/incident-response/cloud-incident-response/SKILL.md) - Blue Detection/Defense Counterpart
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`aws-attacks-s3-and-storage`](../aws-attacks-s3-and-storage/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`aws-attacks-iam-and-role-chaining`](../aws-attacks-iam-and-role-chaining/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `aws-attacks-compute-and-metadata` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 7 |
| Distinct dataset sources | 6 |
| Top sources | CYBER_CPT/gh_advisories (2), bug-bounty-pentest-en (1), CYBER_CPT/wiz_research (1), CYBER_CPT/github_security_md (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
