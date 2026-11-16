---
name: infrastructure-as-code-review
description: "Reviews IaC for security defects: Terraform and CloudFormation misconfigurations, overly permissive policies, and drift between declared and actual state. Use when IaC is available for review."
family: cloud-container-supply-chain
tier: leaf
triggers: ["iac review", "terraform security", "cloudformation review", "infrastructure as code"]
cwe: [CWE-1188]
owasp: []
attack: []
capec: [CAPEC-122]
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
---

# Infrastructure As Code Review - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)

## Mechanism and Preconditions

Infrastructure-as-code review is the only place where the whole estate can be read before it exists, and that is its value and its difficulty. The review has three layers. The declaration: what the code says, which is the resource configuration — encryption flags, public access blocks, IAM statements, network rules. The state: what the provider actually holds, which can differ from the declaration because of drift, imports, or resources created outside the pipeline. The plan: what will change, which is the only artefact that shows the diff the pipeline will apply, and the only one that catches a replacement that destroys and recreates a resource with different properties. Static scanners read the declaration and produce a long list of findings, most of which are already mitigated by a module default or a provider-level setting; the review value comes from reading the plan and the state alongside the declaration so that a finding is a finding about the estate rather than about a file. Policy-as-code — Rego/OPA and Checkov custom policies — is the mechanism that keeps the declaration-to-plan gap closed between reviews.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a static scanner reports a finding **THEN** check the module default and the provider configuration before reporting it; most scanner noise comes from reading the declaration alone.
2. **IF** the question is what will actually change **THEN** the artefact is `terraform plan`, not the source; a replacement is a different risk from an in-place update.
3. **IF** the resource holds state or secrets **THEN** the backend configuration is the finding, not the resource; see [`terraform-state-and-gitops-argocd-security`](../terraform-state-and-gitops-argocd-security/SKILL.md).
4. **IF** the resource is a policy or role **THEN** the finding needs the effective permission, so read the module's inputs as well as the resource.
5. **IF** the repository has no policy-as-code gate **THEN** record the absence; a review that relies on a human reading HCL does not scale and does not survive.
6. **IF** the target is Kubernetes manifests rather than cloud resources **THEN** start at [`kubernetes-pentesting-admission-and-workload-abuse`](../kubernetes-pentesting-admission-and-workload-abuse/SKILL.md) for the pod-level analysis.
7. **IF** the declaration, the state, and the plan agree and the policy gate is in the pipeline **THEN** record `Verified Safe` with the three artefacts you compared.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the backend and provider configuration first.** State location, encryption, locking, and the provider version. A finding about a resource is secondary to a finding about the state store.
2. **Establish the plan.** Run a plan against a read-only credential or read the pipeline's stored plan artefact. The plan shows the diff, which is the only reliable statement about change.
3. **Compare declaration, state, and plan.** Any resource in the state but not the declaration is drift; any resource in the plan with a `replace` action is a different risk class.
4. **Define the baseline-vs-probe differential.** Baseline: the declared resource block and its module defaults. Probe: the planned or applied configuration from `terraform show -json`. A security property present in the declaration but absent in the plan is the finding, and module defaults are the usual reason.
5. **Name the stop condition.** Stop at the first property that differs between the declared intent and the planned result, or the first drift item that widens access. Do not apply anything.
6. **State the proof.** Report the resource address, the declared and planned values, the module or provider default that changed it, and the policy that would prevent it. If all three agree, record the negative with the artefact paths.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A scanner finding on a resource whose module sets the safe value by default | The declaration is a wrapper, so the finding is about the module rather than the call site | Terraform modules, CDK constructs |
| `terraform plan` showing `must be replaced` on a security-relevant resource | A destroy-and-recreate, which changes the resource's identity and often its access | Plan output |
| A resource in state with no declaration | Drift: something changed outside the pipeline, and the next apply may revert or ignore it | State versus code |
| `encryption { ... }` absent but a module input defaulting to enabled | The effective configuration is encrypted, so the finding is a documentation gap | Module inputs |
| A policy document built with `jsonencode` from variables | The effective statement depends on the variable values, so the review needs the `tfvars` too | IAM resources in HCL |
| A `checkov` custom policy in the pipeline | The mechanism that prevents regression, and the control to cite | Policy-as-code gate |

## Worked Contrast

**Vulnerable: resource block that looks encrypted but overrides the module default, with no plan gate**

```hcl
# The module defaults to encryption, but this call disables it and the pipeline has
# no policy gate, so the declaration reads safe and the resource is not.
module "db" {
  source = "git::https://example.com/modules/rds.git?ref=v3.2.0"

  identifier          = "prod-db"
  storage_encrypted   = false          # overrides the module default of true
  publicly_accessible = true
  skip_final_snapshot = true
}
```

**Hardened: safe value not overridden, plan gate, and a policy that fails the build**

```hcl
module "db" {
  source = "git::https://example.com/modules/rds.git?ref=v3.2.0"

  identifier          = "prod-db"
  storage_encrypted   = true           # explicit, matches the module default
  publicly_accessible = false
  skip_final_snapshot = false
  deletion_protection = true
}
```

```python
# checkov custom policy: fail if encryption is disabled or the DB is public
from checkov.terraform.checks.resource.base_resource_check import BaseResourceCheck
from checkov.common.models.enums import CheckResult, CheckCategories

class RdsEncryptedPrivate(BaseResourceCheck):
    def __init__(self):
        super().__init__(name="RDS must be encrypted and private",
                         id="CKV_CUSTOM_1", categories=[CheckCategories.ENCRYPTION])
        self.evaluated_keys = ["storage_encrypted", "publicly_accessible"]

    def scan_resource_conf(self, conf):
        enc = conf.get("storage_encrypted", [True])[0]
        pub = conf.get("publicly_accessible", [False])[0]
        return CheckResult.PASSED if enc is True and pub is False else CheckResult.FAILED

check = RdsEncryptedPrivate()
```

**Why this matters:** The left block reads as a database module call and the danger is one overridden boolean that no reviewer notices, with no plan gate to catch it and no scan rule to fail the build. The right block sets the safe values explicitly, keeps the plan in the pipeline so a replacement is visible, and adds a policy that fails on exactly the two properties that matter.

## When It Is NOT This Issue

- **A scanner finding on a resource inside a module that sets the value safely.** The finding belongs to the module's consumers only if they can override it.
- **A `replace` action on a resource that holds no state and no access.** Recreation is routine for a stateless resource.
- **A `publicly_accessible = true` on a resource in a private subnet with no route.** The property does not reach the internet; state the network argument.
- **Drift on a resource that is deliberately managed out of band.** The finding is the documentation gap, not the drift.
- **A missing `deletion_protection` on a non-production resource.** Note it; the finding needs the data classification.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `infrastructure-as-code-review` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `infrastructure-as-code-review` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: infrastructure-as-code-review
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-1188 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `infrastructure-as-code-review` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-1188`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 19 |
| Distinct dataset sources | 9 |
| Top sources | cyber-security/CyberSec-Dataset (7), CYBER_CPT/L5/ctf_search (3), CYBER_CPT/hacktricks_cloud (2), CYBER_CPT/ctf_search (2) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 10 cases |
| Grounding | multi-dataset corpus-grounded |
