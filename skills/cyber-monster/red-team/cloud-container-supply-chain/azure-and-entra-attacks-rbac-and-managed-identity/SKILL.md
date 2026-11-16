---
name: azure-and-entra-attacks-rbac-and-managed-identity
description: Azure RBAC and managed identity abuse. Covers Azure RBAC role review, managed identity token retrieval and automation account credential paths. Use as the variant-specific playbook when the target matches this profile; start at the parent class skill for general methodology.
family: cloud-container-supply-chain
tier: leaf
triggers: ["azure rbac abuse", "managed identity token", "automation account"]
cwe: [CWE-269]
owasp: []
attack: [T1078]
capec: [CAPEC-122]
related: [azure-and-entra-attacks, azure-and-entra-attacks-token-and-consent-abuse, cloud-recon-and-enumeration, aws-attacks]
parent: azure-and-entra-attacks
---

# Azure and Entra Attacks Rbac and Managed Identity - Red Team Sub-Skill

> **Cyber Monster** | Family: [`Cloud, Container and Supply Chain`](../README.md) | Tier: **leaf** | Paired Counterpart: [`saas-workspace-and-entra-unified-audit-forensics`](../../../blue-team/digital-forensics/saas-workspace-and-entra-unified-audit-forensics/SKILL.md)

## Mechanism and Preconditions

Azure RBAC and managed-identity review is about two different grant surfaces that compose badly. The RBAC surface assigns a role definition to a principal at a scope — subscription, resource group, or resource — and the assignment is inherited down the scope tree, so a role at subscription scope reaches every resource group below it. The identity surface issues tokens: a system-assigned managed identity lives and dies with its resource, a user-assigned one is a separate object that can be attached to many resources, and a federated identity credential binds an external subject (such as a Kubernetes service account) to that identity. The composition is the finding path: a workload that can call the instance metadata endpoint obtains a managed-identity token, and if that identity holds a role assignment at a broad scope, the whole scope is reachable from inside the workload. In AKS the binding is explicit — a federated credential names `system:serviceaccount:<ns>:<sa>` and a client id annotates the service account — so anyone who can create a service account with the right annotation, or patch an existing one, can assume the mapped Azure identity. The 2025 Azure workload identity guidance and the Ratify advisory on token exchange both land on the same control: validate that the token recipient is the intended resource before exchanging.

## Quick Start

Follow these **IF / THEN** decision rules before reading any companion file:

1. **IF** a role assignment's scope is a subscription or management group **THEN** every resource below it is in scope; the finding is the scope, not the role's name.
2. **IF** the identity is user-assigned and attached to more than one resource **THEN** a compromise of any attached resource reaches the same permissions; list the attachments.
3. **IF** the workload runs on AKS with workload identity **THEN** check who can create or patch service accounts with the `azure.workload.identity/client-id` annotation, because that is the assumption primitive.
4. **IF** the identity can read a Key Vault **THEN** the effective data access is the secret set, not the role name; enumerate the vault's secret names.
5. **IF** the identity holds `Contributor` at subscription scope **THEN** the path to `Owner` runs through role-assignment write, which is the escalation to prove.
6. **IF** the question is which token a workload receives **THEN** start at [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) for the token shape.
7. **IF** every assignment is scoped to a single resource group with a role that has no role-assignment write **THEN** record `Verified Safe` with the scope list.

## Variants and Decision Table

| Condition / Need | Target File | Why |
|---|---|---|
| Need parent class methodology | [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) | General class triage before variant specifics |
| Need extra diagnostic checks or SIEM queries | [`PAYLOADS.md`](PAYLOADS.md) | Open only if inline patterns below are insufficient |
| Need CLI syntax, flags, and SDK reference | [`TOOLS.md`](TOOLS.md) | Open when invoking or scripting external tools |
| Need real-world case cards & root causes | [`SCENARIOS.md`](SCENARIOS.md) | Distilled incidents from disclosed reports & corpora |
| Need detection signals | [`DETECTION.md`](DETECTION.md) | Operational handoff & telemetry scope |
| Need in-file case notes | [`CASES.md`](CASES.md) | Labels already in this folder; the procedure is in this SKILL.md |

## Procedure

1. **Map assignments by scope depth.** Collect role assignments with their scope and role definition id, then sort by scope: management group, subscription, resource group, resource. Broad scope plus a privileged role is the first thing to report.
2. **Map identities to resources.** For each user-assigned identity, list every resource it is attached to; for each system-assigned one, the single resource. A federated credential adds an external subject to that list.
3. **Choose the branch.** Over-broad scope, identity reuse across resources, federation subject too permissive, or a role with role-assignment write inside the scope.
4. **Define the baseline-vs-probe differential.** Baseline: `az role assignment list --assignee <identity>` for the identity, which gives its effective roles and scopes. Probe: the same for the identity reachable from a lower-privileged workload, after one hop through federation. A probe that reaches a scope the baseline does not is the chain.
5. **Name the stop condition.** Stop at the first path from a workload an attacker could control to a role assignment at a scope the design did not intend. Do not request a token for a production identity.
6. **State the proof.** Report the assignment id, the scope, the role definition, the attachments of the identity, and the subject that can obtain a token. If every assignment is narrowly scoped and every federation subject is a specific service account, record the negative.

## Concrete Patterns

| Indicator | What it proves | Stack / surface |
|---|---|---|
| `Contributor` assigned at `/subscriptions/<id>` to a user-assigned identity | Every resource in the subscription is modifiable from any workload that identity is attached to | Azure RBAC assignments |
| The same user-assigned identity attached to three different resources | Identity reuse: one compromised workload reaches all three permission sets | AKS kubelet identity, VM identities |
| A federated credential with subject `system:serviceaccount:prod:*` | Any service account in the namespace can assume the identity, which is the wildcard-subject finding | AKS workload identity |
| `azure.workload.identity/client-id` patchable by a broad group | Anyone who can patch the service account becomes the identity | Kubernetes RBAC on serviceaccounts |
| A role definition with `Microsoft.Authorization/roleAssignments/write` | Escalation to `Owner` by assigning a role to yourself | Custom roles, `User Access Administrator` |
| An assignment scoped to a single resource group with `Key Vault Secrets User` | Correct least privilege, and the control to cite | Key Vault data-plane access |

## Worked Contrast

**Vulnerable: user-assigned identity with subscription Contributor, federated to a namespace wildcard**

```bash
# The identity can modify anything in the subscription, it is attached to several
# workloads, and any service account in the namespace can become it.
az role assignment create --assignee-object-id "$IDENTITY" \
  --role "Contributor" --scope "/subscriptions/$SUB"

az identity federated-credential create --name prod-any \
  --identity-name "$IDENTITY" --resource-group rg-apps \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:prod:*" \
  --audience "api://AzureADTokenExchange"
```

**Hardened: resource-group scope, single attachment, exact service-account subject**

```bash
# The identity can manage one resource group, only one workload carries it, and the
# federation names one service account.
az role assignment create --assignee-object-id "$IDENTITY" \
  --role "Key Vault Secrets User" \
  --scope "/subscriptions/$SUB/resourceGroups/rg-apps/providers/Microsoft.KeyVault/vaults/kv-app"

az identity federated-credential create --name prod-api \
  --identity-name "$IDENTITY" --resource-group rg-apps \
  --issuer "$OIDC_ISSUER" \
  --subject "system:serviceaccount:prod:api-sa" \
  --audience "api://AzureADTokenExchange"
```

**Why this matters:** The left identity is a subscription-wide administrator reachable from any pod in the namespace, and because it is attached to several workloads, one compromise covers them all. The right identity can read one vault's secrets, is carried by one workload, and the federated subject names exactly one service account, so the assumption primitive and the resulting permissions are both bounded.

## When It Is NOT This Issue

- **A `Reader` assignment at subscription scope for a monitoring identity.** Broad read is the design; the finding would need a data-plane or write action.
- **A user-assigned identity attached to several resources that all belong to one workload.** Reuse across replicas of the same deployment is not the same as reuse across tenants.
- **A federated credential with a wildcard subject scoped to a dedicated namespace that only the platform team can write to.** The wildcard is bounded by the RBAC on that namespace; state both.
- **A managed identity with no role assignments.** Nothing to reach; the finding would be about the resource it is attached to.
- **A role assignment created by a privileged deployment pipeline.** The pipeline is the intended holder; the finding is whether anything else can take its place.

## Anti-Hallucination Ban List

- **NEVER fabricate CVE identifiers, CVSS vector strings, or vendor advisory URLs** — you MAY cite standard CWE/OWASP/ATT&CK IDs when accurate, but cite specific CVEs only from user input or `CASES.md`.
- **NEVER claim `azure-and-entra-attacks-rbac-and-managed-identity` is exploitable from a string match or HTTP 500 error alone** without verifying reachability and control-vs-probe differential.
- **NEVER generate weaponized exploit payloads, shellcode, C2/implant code, or destructive commands** — prove issues with minimal non-destructive checks and structural fixes.
- **NEVER recommend blocklist filtering as a primary remediation** when typed schemas, bound parameters, or server-side allowlists exist.

## Preconditions Checklist

Verify all five checks before emitting your final output:

- [ ] **Preconditions verified:** Every required boundary/sink/logsource for `azure-and-entra-attacks-rbac-and-managed-identity` was confirmed in the input, not assumed.
- [ ] **False-positive traps ruled out:** None of the negative conditions in *When It Is NOT This Issue* apply.
- [ ] **Zero fabricated citations:** Every CVE, CWE, CLI flag, or API name is verbatim from the user input or this skill.
- [ ] **Concrete remediation / action:** Fix, rule, or script is specific and actionable (no generic 'sanitize inputs' advice).
- [ ] **Output Contract followed:** Response uses the exact headings in *Strict Output Contract* below.

## Strict Output Contract

Use this structure for your answer unless the user explicitly asks for a different format:

```markdown
### Security Assessment Finding: azure-and-entra-attacks-rbac-and-managed-identity
- **Verdict & Confidence**: [Confirmed Vulnerable | Non-Exploitable / False Positive | Needs Runtime Verification] (Confidence: High/Medium/Low)
- **Preconditions & Surface**: [Entry point, trust boundary, and exact sink/config reached]
- **Verified Evidence**: [Minimal non-destructive check vs baseline, or exact vulnerable lines]
- **Root Cause & Taxonomy**: [Broken security invariant; CWE: CWE-269 | Mapping: T1078]
- **Concrete Remediation**: [Idiomatic code diff or configuration change + verification test]
```

## Related Sub-Skills

- [`saas-workspace-and-entra-unified-audit-forensics`](../../../blue-team/digital-forensics/saas-workspace-and-entra-unified-audit-forensics/SKILL.md) - Blue Detection/Defense Counterpart
- [`azure-and-entra-attacks`](../azure-and-entra-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`azure-and-entra-attacks-token-and-consent-abuse`](../azure-and-entra-attacks-token-and-consent-abuse/SKILL.md) - Cloud, Container and Supply Chain (leaf)
- [`cloud-recon-and-enumeration`](../cloud-recon-and-enumeration/SKILL.md) - Cloud, Container and Supply Chain (core)
- [`aws-attacks`](../aws-attacks/SKILL.md) - Cloud, Container and Supply Chain (flagship)
- [`gcp-attacks`](../gcp-attacks/SKILL.md) - Cloud, Container and Supply Chain (core)

## Operating Notes

- **Self-contained 1-read design:** This `SKILL.md` handles ~80% of `azure-and-entra-attacks-rbac-and-managed-identity` tasks directly; only open companions when a row in *Variants and Decision Table* applies.
- **Taxonomy framing:** Keep framework references concise (parent CWE/ATT&CK categories `CWE-269, T1078`).
- **Safety & authorization:** Perform only non-destructive verification and defensible engineering within authorized scope.

## Evidence Base

| Dimension | Value |
|---|---|
| Corpus records | 8 |
| Distinct dataset sources | 5 |
| Top sources | CYBER_CPT/hacktricks_cloud (3), CYBER_CPT/kubernetes_goat (2), CYBER_CPT/github_security_md (1), CYBER_CPT/heresecurity (1) |
| Worked contrasts & slot items | 1 inline worked contrast + 0 code / 2 det / 0 tools / 6 cases |
| Grounding | multi-dataset corpus-grounded |
