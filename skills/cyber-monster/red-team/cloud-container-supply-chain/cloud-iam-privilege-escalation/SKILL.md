---
name: cloud-iam-privilege-escalation
description: "Finds and exploits cloud IAM escalation paths: overly permissive policies, pass-role and create-policy primitives, trust policy weaknesses and identity chaining across accounts. Use when reviewing cloud permissions."
family: cloud-container-supply-chain
tier: core
triggers: ["cloud iam privesc", "iam escalation", "passrole", "trust policy", "privilege escalation cloud"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
---

# Cloud IAM Privilege Escalation - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Cloud privilege escalation is the composition of permissions into a path, and the permission sets that matter are small and enumerable per provider. On AWS the primitives are `iam:PassRole`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutRolePolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey`, `iam:CreateLoginProfile`, and `sts:AssumeRole` on a role whose trust admits the principal. On Azure the primitives are `Microsoft.Authorization/roleAssignments/write` at a scope, `Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write`, and the `Contributor`-to-`Owner` step through role assignment. On GCP the primitives are `iam.serviceAccounts.actAs`, `iam.serviceAccountKeys.create`, `iam.serviceAccounts.setIamPolicy`, and `resourcemanager.projects.setIamPolicy`. The review method is the same in all three: build the directed graph, then ask whether a path exists from a principal an attacker could hold to a role whose definition includes the primitive itself. A single hop is a finding only when the starting principal is attacker-reachable; otherwise it is an inventory entry, and the distinction is most of the report's quality.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a principal holds a primitive whose target includes a privileged role **THEN** that is one hop; enumerate the target's permissions before writing the finding.
2. **IF** the primitive is `roleAssignments/write` or `projects.setIamPolicy` **THEN** it is self-sufficient, because the principal can grant itself anything in that scope.
3. **IF** the starting principal is not attacker-reachable **THEN** the finding is conditional; state the precondition rather than the severity.
4. **IF** the path is provider-specific **THEN** stay in the provider's skill ([`aws-attacks-iam-and-role-chaining`](../aws-attacks-iam-and-role-chaining/SKILL.md), [`azure-and-entra-attacks-rbac-and-managed-identity`](../azure-and-entra-attacks-rbac-and-managed-identity/SKILL.md), [`gcp-attacks`](../gcp-attacks/SKILL.md)) and use this skill for the comparison and the graph method.
5. **IF** the escalation requires a workload to run code **THEN** add the compute path from the provider's compute skill.
6. **IF** the estate uses a permission boundary or SCP **THEN** check it at the top of the path, because it constrains the starting principal and not the target.
7. **IF** no path exists from an attacker-reachable principal **THEN** record `Verified Safe` with the graph size and the principals checked.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Define the start set.** The principals an attacker could plausibly hold: a CI role, a workload identity, a low-privilege user, a federated external identity. A path from an administrator is not a finding.
2. **Define the goal set.** Roles whose definitions include a primitive, or that grant data access the design says is protected.
3. **Build the graph with the provider's own evaluator where possible.** `simulate-principal-policy` on AWS, role-assignment enumeration on Azure, `get-iam-policy` plus `actAs` on GCP. The evaluator's answer is the evidence.
4. **Choose the branch.** Single self-sufficient primitive, two-hop chain, trust-policy edge, or a federation edge.
5. **Name the stop condition.** Stop at the first path from the start set to the goal set, and stop at two hops unless a third is needed to show reachability. Do not execute a hop.
6. **State the proof.** Report each node and edge, the evaluator result at each end, and the single change that breaks the path. If no path exists, report the graph size and the reachable set, which is the useful negative.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| AWS `iam:CreatePolicyVersion` on `*` | Policy mutation on any policy, including one attached to an administrative role | IAM identity policies |
| Azure `roleAssignments/write` at subscription scope | Self-sufficient escalation to `Owner` by assigning a role to yourself | Azure RBAC |
| GCP `iam.serviceAccounts.actAs` on an account with `roles/owner` | Two-hop escalation through impersonation | GCP IAM |
| AWS `sts:AssumeRole` on a role whose trust names the principal's account root | A trust edge an attacker with any principal in that account can use | Role trust policies |
| Azure federated credential subject with a namespace wildcard | Any service account in the namespace can assume the identity | AKS workload identity |
| GCP `resourcemanager.projects.setIamPolicy` at project scope | Self-sufficient escalation within the project, no second hop needed | GCP IAM policies |

## Worked Contrast

**Vulnerable: self-sufficient role-assignment write granted to a CI identity**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": ["iam:CreatePolicyVersion", "iam:AttachRolePolicy"],
    "Resource": "*"
  }]
}
```

```yaml
# Azure equivalent: the pipeline's identity can write role assignments anywhere
- role: "Role Based Access Control Administrator"
  scope: "/subscriptions/00000000-0000-0000-0000-000000000000"
```

**Hardened: deploy role limited to the resources it deploys, no policy or assignment writes**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect": "Allow", "Action": ["lambda:UpdateFunctionCode", "lambda:GetFunction"],
     "Resource": "arn:aws:lambda:eu-west-1:111122223333:function:api-*"},
    {"Effect": "Allow", "Action": "iam:PassRole",
     "Resource": "arn:aws:iam::111122223333:role/api-exec",
     "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}}
  ]
}
```

```yaml
# Azure: a built-in role scoped to the resource group, with no assignment write
- role: "Website Contributor"
  scope: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-api"
```

**Why this matters:** The left grants are self-sufficient: `CreatePolicyVersion` and `AttachRolePolicy` on `*` let the holder attach any permission to any role it can use, and the Azure equivalent lets the pipeline assign itself `Owner` at subscription scope. The right grants let the pipeline update one function's code and pass one narrowly scoped execution role, so there is no edge from the pipeline to a new permission.

## When It Is NOT This Issue

- **A primitive scoped to resources the principal already controls.** `CreatePolicyVersion` on a policy attached only to the principal's own role grants nothing new.
- **`iam:PassRole` with `iam:PassedToService` and a single role ARN.** The role cannot be handed elsewhere.
- **A trust edge to a principal that is itself the intended holder.** The chain starts and ends in the same place.
- **`roleAssignments/write` at a single resource scope for a principal that is the resource's owner.** Bounded by the scope.
- **A path that requires an administrator principal.** Not attacker-reachable; record it as an inventory entry with the precondition.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `cloud-iam-privilege-escalation` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `cloud-iam-privilege-escalation` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: cloud-iam-privilege-escalation
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md) - Blue Detection/Defense Counterpart
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-storage-and-metadata-abuse`](../cloud-storage-and-metadata-abuse/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `cloud-iam-privilege-escalation` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 12 |
| Distinct dataset sources | 4 |
| Top sources | CYBER_CPT/hacktricks_cloud (9), SecEval/attck (1), bug-bounty-pentest-en (1), CYBER_CPT/go_exploitdb (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
