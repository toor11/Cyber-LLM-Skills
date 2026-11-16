---
name: gcp-attacks
description: "Assesses and exploits GCP: service account key exposure, IAM binding weaknesses, Cloud Storage exposure and metadata service abuse. Use when the target runs on GCP."
family: cloud-container-supply-chain
tier: core
triggers: ["gcp attack", "gcp pentest", "service account abuse", "gcs bucket", "google cloud attack"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [cloud-recon-and-enumeration, aws-attacks, azure-and-entra-attacks, cloud-iam-privilege-escalation]
corpus_sparse: true
---

# GCP Attacks - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **core** | Paired Counterpart: [`cloud-detection-and-logging`](../../../blue-team/detection-and-monitoring/cloud-detection-and-logging/SKILL.md)
> **Grounding note:** fewer than three corpus records matched this exact leaf (`corpus_sparse: true`). Guidance below is compiled from authoritative CWE/OWASP/ATT&CK specifications and verified engineering blueprints.

## Mechanism and Preconditions

GCP review centres on the IAM policy hierarchy and on service-account key material. The hierarchy is additive: an `allow` at the organisation, folder, project, or resource applies to everything beneath it, and there is no deny except through `deny` policies and IAM Conditions, so a broad grant near the root is effectively organisation-wide. The escalation primitives are concentrated and enumerable: `iam.serviceAccounts.actAs` (which is required for almost every compute service to run as a service account, and therefore the most valuable single permission), `iam.serviceAccountKeys.create` (mint a permanent credential), `iam.serviceAccounts.setIamPolicy` (grant yourself `actAs`), `resourcemanager.projects.setIamPolicy` (grant anything at project scope), and `iam.roles.update` (edit a custom role you already hold). Service-account keys are the other half: a JSON key is a permanent credential with no expiry, which is why organisations created on or after 3 May 2024 have `constraints/iam.managed.disableServiceAccountKeyCreation` and `constraints/iam.managed.disableServiceAccountKeyUpload` enforced by default, and why Workload Identity Federation — OIDC or SAML token exchange for a short-lived credential — is the documented replacement for external workloads.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a principal holds `iam.serviceAccounts.actAs` on a service account with broad roles **THEN** that is the escalation hop; enumerate the service account's roles next.
2. **IF** a principal holds `iam.serviceAccountKeys.create` **THEN** it can mint a permanent credential, which is a persistence finding independent of the roles it holds today.
3. **IF** the organisation policy for key creation is not enforced **THEN** record the constraint name and the inheritance point where it is missing.
4. **IF** an external workload authenticates to GCP **THEN** check whether Workload Identity Federation is in use; a JSON key for the same workload is the finding.
5. **IF** a Workload Identity Pool provider accepts a broad attribute condition **THEN** the federation is effectively open; the condition is the security boundary.
6. **IF** the question is a GKE workload identity mapping **THEN** check which Kubernetes service accounts can act as which GCP service account.
7. **IF** the question is a container that runs on GKE with a mounted token **THEN** switch to [`kubernetes-pentesting-rbac-and-service-accounts`](../kubernetes-pentesting-rbac-and-service-accounts/SKILL.md) for the cluster-side grant.
8. **IF** every grant is a predefined role at project scope with no `actAs` and no key creation **THEN** record `Verified Safe` with the constraint and role list.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Walk the policy hierarchy from the resource up.** Collect `allow` policies at resource, project, folder, and organisation, plus any `deny` policies and IAM Conditions. Effective permission is the union, minus denies, filtered by conditions.
2. **Enumerate the escalation primitives held.** `actAs`, `serviceAccountKeys.create`, `serviceAccounts.setIamPolicy`, `projects.setIamPolicy`, `roles.update`, `deployments.create`, and `cloudfunctions.functions.create`. Each is a hop; the report needs the target.
3. **Choose the branch.** Over-broad inherited grant, `actAs` escalation, key-creation persistence, or federation condition too broad.
4. **Define the baseline-vs-probe differential.** Baseline: `gcloud projects get-iam-policy` for the caller's own principal, which lists its direct grants. Probe: the same policy read for a service account the caller can `actAs`, which lists what the hop reaches. The differential is the set of roles the probe adds.
5. **Name the stop condition.** Stop at the first path from a principal an attacker could hold to a role that grants `setIamPolicy` or data access. Do not mint a key or impersonate a service account.
6. **State the proof.** Report each hop with the permission, the resource, and any condition; the inherited grant with its inheritance point; and the constraint that would close it (disable key creation, restrict `actAs`, narrow the pool condition).

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `roles/editor` granted at organisation or folder scope | Every resource beneath is editable, which is the broadest practical grant short of owner | Resource Manager IAM policies |
| `iam.serviceAccounts.actAs` on a service account holding `roles/owner` | A two-hop escalation: act as the account, then use its roles | Compute, Cloud Run, and Cloud Functions deploy permissions |
| `iam.serviceAccountKeys.create` with no constraint | Permanent credential minting, which survives password rotation and policy review | IAM policies, CI service accounts |
| `constraints/iam.managed.disableServiceAccountKeyCreation` enforced at the org | The control that makes key creation impossible below it, and the citation for a non-finding | Organisation Policy |
| A Workload Identity Pool provider with `attributeCondition: "true"` | Any token from the issuer maps to the pool, so the federation is open to the issuer's whole population | Workload Identity Federation |
| A Kubernetes service account annotated to a GCP service account with broad roles | The GKE hop: anyone who can schedule a pod with that service account reaches those roles | GKE Workload Identity |

## Worked Contrast

**Vulnerable: editor at folder scope, actAs on a privileged account, key creation allowed**

```hcl
# Inherited editor plus the actAs hop, with no constraint preventing key creation.
resource "google_folder_iam_member" "broad" {
  folder = google_folder.apps.name
  role   = "roles/editor"
  member = "group:contractors@example.com"
}

resource "google_service_account_iam_member" "actas" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.serviceAccountUser"
  member             = "group:contractors@example.com"
}
```

**Hardened: predefined roles at project scope, actAs limited to one account, key creation blocked**

```hcl
# A narrow predefined role at project scope, actAs for one deploy account, and the
# organisation constraint that makes key creation impossible below it.
resource "google_project_iam_member" "deploy" {
  project = var.project_id
  role    = "roles/run.developer"
  member  = "group:platform@example.com"
}

resource "google_service_account_iam_member" "actas" {
  service_account_id = google_service_account.deploy.name
  role               = "roles/iam.serviceAccountUser"
  member             = "group:platform@example.com"
  condition {
    title      = "deploy-window"
    expression = "request.time.getHours('UTC') >= 8 && request.time.getHours('UTC') < 18"
  }
}

resource "google_org_policy_policy" "no_keys" {
  parent = "organizations/${var.org_id}"
  name   = "organizations/${var.org_id}/policies/iam.managed.disableServiceAccountKeyCreation"
  spec { rules { enforce = "TRUE" } }
}
```

**Why this matters:** The left configuration gives a contractor group editor over every resource in the folder and the ability to act as the deploy account, and nothing stops them minting a permanent key from it. The right configuration narrows the role, keeps `actAs` to one account inside a time condition, and enforces the key-creation constraint at the organisation so the persistence path does not exist.

## When It Is NOT This Issue

- **A predefined role granted at project scope to a group.** That is the ordinary least-privilege shape; the finding would need a primitive inside the role.
- **`roles/iam.serviceAccountUser` on one account with a condition.** The condition is a real bound; report the expression rather than the role.
- **A service-account key in a legacy project where the constraint is enforced at a higher folder with an exception tag.** The exception is documented; the finding is the exception's scope.
- **A Workload Identity Pool provider whose `attributeCondition` restricts to a repository and a ref.** That is the correct configuration.
- **`roles/viewer` inherited from the organisation.** Broad read of metadata; the finding needs a data-plane action.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `gcp-attacks` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `gcp-attacks` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: gcp-attacks
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
- [`cloud-iam-privilege-escalation`](../cloud-iam-privilege-escalation/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`cloud-storage-and-metadata-abuse`](../cloud-storage-and-metadata-abuse/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `gcp-attacks` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 1 |
| Distinct dataset sources | 1 |
| Top sources | bugbounty-hunter-v1 (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 0 det / 0 tools / 0 cases |
| Grounding | reference frameworks & engineering blueprint (corpus_sparse) |
