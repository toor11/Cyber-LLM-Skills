# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`azure-and-entra-attacks-rbac-and-managed-identity`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Az - Azure Automation Accounts Privesc

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Az - Azure Automation Accounts Privesc ## Azure Automation Accounts ### Hybrid Workers Group - **From the Automation Account to the VM** Remember that if somehow an attacker can execute an arbitrary runbook (arbitrary code) in a hybrid worker, he will **pivot to the location of
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Az - Automation Accounts

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Az - Automation Accounts ## Basic Information Azure Automation Accounts are cloud-based services in Microsoft Azure that help **automate tasks** like resource management, configuration, and updates across Azure and on-premises environments. They provide **Runbooks** (scripts fo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Kubernetes Role-Based Access Control(RBAC)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Kubernetes Role-Based Access Control (RBAC) ## Role-Based Access Control (RBAC) Kubernetes has an **authorization module named Role-Based Access Control** ([**RBAC**] (https://kubernetes.io/docs/reference/access-authn-authz/rbac/)) that helps to set utilization permissions to th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: ⎈ RBAC least privileges misconfiguration

- **Provenance:** Source: `CYBER_CPT/kubernetes_goat` | CWE: `CWE-269`
- **Context / Surface:** Source: kubernetes_goat (en)
- **Root Cause / Analysis:** # ⎈ RBAC least privileges misconfiguration ## 🙌 Overview In the early days of Kubernetes, there is no such concept as RBAC (role-based access control) and mostly it uses ABAC (attribute-based access control). Now it has superpowers like RBAC to implement the security principle of
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: ⎈ Helm v2 tiller to PwN the cluster - [Deprecated]

- **Provenance:** Source: `CYBER_CPT/kubernetes_goat` | CWE: `CWE-269`
- **Context / Surface:** Source: kubernetes_goat (en)
- **Root Cause / Analysis:** # ⎈ Helm v2 tiller to PwN the cluster - [Deprecated] :::warning This scenario has been deprecated from the Kubernetes Goat and read-only documentation is available to learn 😊 ::: ## 🙌 Overview This is one of the early days of Kubernetes package manager configuration mistakes. Hel
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Kyverno: Cross-Namespace Read Bypasses RBAC Isolation (CVE-2026-22039 Incomplete Fix)

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary CVE-2026-22039 fixed cross-namespace privilege escalation in Kyverno's 'apiCall' context by validating the 'URLPath' field. However, the **ConfigMap context loader has the identical vulnerability** — the 'configMap.namespace' field accepts any namespace with zero vali
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
