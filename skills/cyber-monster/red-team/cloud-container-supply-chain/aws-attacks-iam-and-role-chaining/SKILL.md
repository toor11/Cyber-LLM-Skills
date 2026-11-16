---
name: aws-attacks-iam-and-role-chaining
description: AWS IAM and role chaining. Covers IAM policy analysis, privilege escalation primitives, role assumption chains and cross-account trust exploitation. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["aws iam privesc", "role chaining", "assume role", "aws policy analysis"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [aws-attacks, aws-attacks-s3-and-storage, aws-attacks-compute-and-metadata, cloud-recon-and-enumeration]
parent: aws-attacks
---

# AWS Attacks IAM and Role Chaining - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-incident-response`](../../../blue-team/incident-response/cloud-incident-response/SKILL.md)

## Mechanism and Preconditions

Role chaining is the composition of IAM grants into a path. The primitives that make it possible are narrow and enumerable: `iam:PassRole` (hand a role to a service that will run with it), `iam:CreatePolicyVersion` with `SetAsDefault` (rewrite a policy that a more privileged principal uses), `iam:AttachRolePolicy` or `iam:PutRolePolicy` (add permissions to a role you do not own), `iam:UpdateAssumeRolePolicy` (change who can assume a role), `iam:CreateAccessKey` on another user, and `sts:AssumeRole` on a role whose trust policy admits you. Each is harmless alone and dangerous in combination, which is why the review requires a graph rather than a checklist. The trust side has its own failure mode: a role that trusts an account root without `sts:ExternalId` can be assumed by any principal in that account that has `sts:AssumeRole`, and a role that trusts a service principal without `aws:SourceArn` or `aws:SourceAccount` can be triggered by another account's resource — the confused deputy. In 2025 the Identity Center additions matter here because `identitystore:UserId` lets a trust policy require a specific verified user, which closes the "any federated user in the tenant" version of the same problem.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a principal holds `iam:PassRole` on `*` or on a privileged role **THEN** that is hop one; enumerate the target role's permissions next.
2. **IF** a principal can call `iam:CreatePolicyVersion` or `iam:PutRolePolicy` on a policy attached to a more privileged role **THEN** that is a permission-mutation hop and it needs no `PassRole` at all.
3. **IF** a trust policy names an account root without `sts:ExternalId` **THEN** every principal in that account with `sts:AssumeRole` is a candidate; the finding is the missing condition.
4. **IF** a trust policy names a service principal without `aws:SourceArn` or `aws:SourceAccount` **THEN** the confused-deputy branch applies.
5. **IF** the estate uses Identity Center **THEN** check for `identitystore:UserId` conditions and treat their absence as a broad-federation finding.
6. **IF** the question is only which actions a single principal has **THEN** start at [`aws-attacks`](../aws-attacks/SKILL.md); this skill is about paths of two or more hops.
7. **IF** the chain requires a principal outside the threat model, such as an account administrator **THEN** record `Not Reachable` and name the assumption that would change it.

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

1. **List the escalation primitives held by each principal.** Restrict the search to the six actions above plus `sts:AssumeRole`; a full action inventory is noise.
2. **Resolve each primitive's target.** For `PassRole`, the role ARNs in the `Resource`; for policy mutation, the policies attached to privileged roles; for `AssumeRole`, the roles whose trust admits the principal.
3. **Walk the graph to a privileged action.** Two hops is the common case: pass a role to a service and run code, or mutate a policy attached to a role you can assume.
4. **Define the baseline-vs-probe differential.** Baseline: `simulate-principal-policy` for the start principal against the final action. Probe: the same for the intermediate role. A denied baseline with an allowed probe, connected by a grant, is the chain.
5. **Name the stop condition.** Stop at the first two-hop path to a privileged action. Do not execute either hop.
6. **State the proof.** Report each hop with the grant, the resource, and any condition; the simulation results at both ends; and the single change that breaks the chain (scope `PassRole`, add `ExternalId`, remove the policy-mutation grant).

## Concrete Patterns

| Indicator | What it proves | Stack or surface |
|---|---|---|
| `iam:PassRole` on `*` plus `lambda:CreateFunction` | A two-hop chain: create a function with a privileged role and invoke it | CI runner roles, developer sandbox roles |
| `iam:CreatePolicyVersion` on a policy attached to an admin role | Permission mutation without `PassRole`; a single hop to full control | Delegated IAM administration roles |
| `iam:UpdateAssumeRolePolicy` on a privileged role | Trust mutation: add your own principal and assume the role | IAM administration roles |
| A trust policy with `Principal: {"AWS": "arn:aws:iam::111122223333:root"}` and no `sts:ExternalId` | Every principal in that account with `sts:AssumeRole` can enter | Cross-account vendor access |
| `aws:SourceAccount` on a service-principal trust | Confused-deputy control present, so the hop is scoped | Lambda, EventBridge, CloudTrail service roles |
| `identitystore:UserId` in a condition block | Identity Center binding to a verified user, which closes the broad-federation hop | IAM Identity Center assignments |

## Worked Contrast

**Vulnerable: two-hop chain through policy mutation and an open trust**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "iam:CreatePolicyVersion", "Resource": "*"},
    {"Effect": "Allow", "Action": "sts:AssumeRole", "Resource": "arn:aws:iam::111122223333:role/build"}
  ]
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
    "Action": "sts:AssumeRole"
  }
}
```

**Hardened: policy mutation scoped to a sandbox, trust pinned to one role with an external id**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": "iam:CreatePolicyVersion",
     "Resource": "arn:aws:iam::111122223333:policy/sandbox-*"},
    {"Effect": "Allow", "Action": "sts:AssumeRole",
     "Resource": "arn:aws:iam::111122223333:role/build",
     "Condition": {"StringEquals": {"sts:ExternalId": "pipeline-4b81"}}}
  ]
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": {
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::111122223333:role/ci-worker"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": {"sts:ExternalId": "pipeline-4b81"},
      "ArnLike": {"aws:PrincipalArn": "arn:aws:iam::111122223333:role/ci-worker"}
    }
  }
}
```

**Why this matters:** The left policy lets its holder rewrite any policy in the account, including one attached to an administrative role, and the role it can assume is open to the whole account. The right policy restricts mutation to sandbox-scoped policies and requires an external id plus a specific principal ARN on the trust, so neither the mutation nor the assumption is available to a principal the pipeline did not create.

## When It Is NOT This Issue

- **`iam:CreatePolicyVersion` scoped to policies whose names encode a sandbox.** The grant is real but the blast radius is bounded; report the scope rather than the action.
- **A trust policy with an account-root principal and a `sts:ExternalId` condition.** The external id is the control for exactly this shape.
- **A service-principal trust with `aws:SourceAccount`.** Correct pattern, not a confused deputy.
- **`sts:AssumeRole` on a role the principal already administers.** No privilege gained; the chain has no effect.
- **A `PassRole` grant with `iam:PassedToService` restricting the target service.** The role cannot be handed to an arbitrary compute service.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `aws-attacks-iam-and-role-chaining` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `aws-attacks-iam-and-role-chaining` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: aws-attacks-iam-and-role-chaining
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
- [`aws-attacks-compute-and-metadata`](../aws-attacks-compute-and-metadata/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `aws-attacks-iam-and-role-chaining` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 5 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/gh_advisories (2), CYBER_CPT/sigmahq (1), CYBER_CPT/github_security_md (1), CYBER_CPT/osv (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 5 cases |
| Grounding | multi-dataset corpus-grounded |
