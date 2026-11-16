---
name: terraform-state-and-gitops-argocd-security
description: "Audits Terraform remote state backends (plaintext secrets in `.tfstate`, state-lock tampering) and GitOps controllers (ArgoCD, Flux): AppProject namespace/cluster wildcard escapes, Helm/Kustomize remote URL injection, and drift reconciliation privilege paths. Use when reviewing IaC state and GitOps deployments."
family: cloud-container-supply-chain
tier: leaf
triggers: ["terraform tfstate secrets", "argocd security", "flux gitops", "appproject rbac", "iac state backend"]
cwe: [CWE-312, CWE-269]
owasp: []
attack: []
capec: []
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, gcp-attacks]
corpus_sparse: true
---

# Terraform State and Gitops Argocd Security - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

Terraform state and GitOps repositories are control planes, and their security properties are different from the resources they manage. State holds every attribute of every managed resource, including values marked `sensitive` — which only suppresses CLI output, not storage — so a state file in an unencrypted bucket is a credential store. The backend configuration is therefore the primary finding: encryption at rest, access restricted to the pipeline role, versioning on, and locking so two applies cannot interleave. OpenTofu added native encryption of state and plan files with key providers such as AWS KMS, GCP KMS, Azure Key Vault, or OpenBao, which changes the answer for organisations on that fork, and its documentation is explicit that encryption does not protect against data loss or replay. On the GitOps side, Argo CD's authority is its repository credential set and the AppProject's source and destination constraints: an AppProject that permits any repository and any namespace lets anyone who can write to a repository deploy anything, and the 2025 Argo CD project-token advisory showed that a token with ordinary project permissions could read repository credentials through the detailed project endpoint, which is why patch levels matter as much as configuration.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** the state backend is unencrypted, unversioned, or readable by a principal other than the pipeline **THEN** that is the finding; the resource configuration is secondary.
2. **IF** the backend has no locking **THEN** concurrent applies can interleave, which is an integrity finding rather than a confidentiality one.
3. **IF** an AppProject permits any source repository **THEN** anyone with write access to any repository can deploy, which is the GitOps equivalent of the state finding.
4. **IF** an AppProject permits cluster-scoped destination resources **THEN** the project can create cluster roles and namespaces, which is beyond a namespace-scoped team.
5. **IF** the Argo CD version predates the project-token fix **THEN** record the version and the advisory class, because a project token can read repository credentials.
6. **IF** the question is what the resources do rather than how they are stored **THEN** start at [`infrastructure-as-code-review`](../infrastructure-as-code-review/SKILL.md).
7. **IF** the state is encrypted with a KMS key, access is limited to the pipeline role, versioning and locking are on, and the AppProject is scoped **THEN** record `Verified Safe` with both artefacts.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Read the backend block.** Type, bucket or address, encryption flag, `kms_key_id`, versioning, and `dynamodb_table` or the equivalent locking mechanism. This is five lines that decide the state's exposure.
2. **Check who can read the state.** The bucket policy and the IAM principals with `s3:GetObject` on the state prefix. A state bucket readable by a broad role is the finding even if encrypted, because the encryption key is available to the same role.
3. **Read the AppProject.** `spec.sourceRepos`, `spec.destinations`, and `spec.clusterResourceWhitelist`. An AppProject is the GitOps authorisation boundary and it is usually far broader than the team it serves.
4. **Define the baseline-vs-probe differential.** Baseline: the backend block and the AppProject spec as written. Probe: the effective access — a read attempt from a non-pipeline principal on the state object, and an Application submitted against a repository outside the intended set. Refusal is the control; success is the finding.
5. **Name the stop condition.** Stop at the first principal that can read state without being the pipeline, or the first AppProject field that admits an unintended source or destination. Do not read state contents.
6. **State the proof.** Report the backend configuration, the readable principals, the AppProject fields, and the version if an advisory applies. If both are scoped, record the negative with the block and spec excerpts.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| A `backend "s3"` block with no `encrypt = true` and no `kms_key_id` | State at rest in plaintext, containing every resource attribute including sensitive values | Terraform backend blocks |
| A state bucket policy granting `s3:GetObject` to a broad role | Any principal with that role reads every attribute of the estate | S3 bucket policies on state buckets |
| A backend with no `dynamodb_table` or equivalent lock | Concurrent applies interleave and can corrupt state or produce partial configurations | Backend configuration |
| An AppProject with `sourceRepos: ["*"]` | Any repository can be a deployment source, so repository write is deployment authority | Argo CD AppProject |
| An AppProject with `clusterResourceWhitelist: [{group: "*", kind: "*"}]` | The project can create cluster-scoped resources, which is beyond a namespace team | Argo CD AppProject |
| OpenTofu `encryption { ... }` with a KMS key provider | Native state encryption, which is the control on that fork | OpenTofu 1.7+ |

## Worked Contrast

**Vulnerable: plaintext state in a broadly readable bucket, and an unrestricted AppProject**

```hcl
terraform {
  backend "s3" {
    bucket = "acme-terraform-state"
    key    = "prod/terraform.tfstate"
    region = "eu-west-1"
    # no encrypt, no kms_key_id, no dynamodb_table
  }
}
```

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: platform
spec:
  sourceRepos: ["*"]
  destinations:
    - namespace: "*"
      server: "*"
  clusterResourceWhitelist:
    - group: "*"
      kind: "*"
```

**Hardened: encrypted and locked state readable only by the pipeline, and a scoped AppProject**

```hcl
terraform {
  backend "s3" {
    bucket         = "acme-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "eu-west-1"
    encrypt        = true
    kms_key_id     = "arn:aws:kms:eu-west-1:111122223333:key/9a1c"
    dynamodb_table = "terraform-locks"
  }
}
```

```yaml
apiVersion: argoproj.io/v1alpha1
kind: AppProject
metadata:
  name: payments
spec:
  sourceRepos:
    - "https://git.example.com/platform/payments-deploy.git"
  destinations:
    - namespace: "payments-*"
      server: "https://kubernetes.default.svc"
  clusterResourceWhitelist: []
  namespaceResourceBlacklist:
    - group: ""
      kind: ResourceQuota
```

**Why this matters:** The left state is plaintext in a bucket whose readers hold both the data and, typically, the ability to read the encryption key, so state access equals infrastructure control; the AppProject admits any repository and any cluster resource, so repository write is cluster admin. The right state is encrypted with a dedicated key, locked, and readable only by the pipeline, and the project admits one repository and one namespace pattern with no cluster-scoped resources.

## When It Is NOT This Issue

- **A state bucket readable by the pipeline role only.** That is the correct scope even without KMS if the bucket itself is encrypted at rest by default.
- **An AppProject with `sourceRepos` naming several repositories that all belong to the same team.** Multiple sources are not the same as `*`.
- **State in a local backend on an ephemeral CI runner.** The state is destroyed with the runner; the finding would be the absence of a shared backend rather than exposure.
- **An Argo CD admin token held by the platform team.** Administrative access is the design; the finding is who else holds it.
- **`clusterResourceWhitelist: []` with a namespace-scoped project.** Correct scoping.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `terraform-state-and-gitops-argocd-security` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `terraform-state-and-gitops-argocd-security` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: terraform-state-and-gitops-argocd-security
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-312, CWE-269 | Mapping: Domain Invariant]
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

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `terraform-state-and-gitops-argocd-security` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-312, CWE-269`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 0 |
| Distinct dataset sources | 0 |
| Top sources | authored blueprints & CWE/ATT&CK specs |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
