# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`authorization-and-idor-property-level`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Mass Assignment (CWE-915) – Privilege Escalation via Unsafe Model Binding

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-915`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Mass Assignment (CWE-915) – Privilege Escalation via Unsafe Model Binding Mass assignment (a.k.a. insecure object binding) happens when an API/controller takes user-supplied JSON and directly binds it to a server-side model/entity without an explicit allow-list of fields.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: WWBN AVideo Affected by a PayPal IPN Replay Attack Enabling Wallet Balance Inflation via Missing Tra

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-915`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The PayPal IPN v1 handler at 'plugin/PayPalYPT/ipn.php' lacks transaction deduplication, allowing an attacker to replay a single legitimate IPN notification to repeatedly inflate their wallet balance and renew subscriptions. The newer 'ipnV2.php' and 'webhook.php' hand
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: DeFi AMM Accounting Bugs & Virtual Balance Cache Exploitation

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-915`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # DeFi AMM Accounting Bugs & Virtual Balance Cache Exploitation ## Overview Yearn Finance's yETH pool (Nov 2025) exposed how gas-saving caches inside complex AMMs can be weaponized when they are not reconciled during boundary-state transitions. The weighted stableswap pool tracks
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Kubernetes Role-Based Access Control(RBAC)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-915`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Kubernetes Role-Based Access Control (RBAC) ## Role-Based Access Control (RBAC) Kubernetes has an **authorization module named Role-Based Access Control** ([**RBAC**] (https://kubernetes.io/docs/reference/access-authn-authz/rbac/)) that helps to set utilization permissions to th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Flowise Allows Mass Assignment in '/api/v1/leads' Endpoint

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-915`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary **A Mass Assignment vulnerability in the '/api/v1/leads' endpoint allows any unauthenticated user to control internal entity fields ('id', 'createdDate', 'chatId') by including them in the request body.** The endpoint uses 'Object.assign()' to copy all properties from
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Web Mass Assignment Vulnerabilities (Login Page)

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-915`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** Asset manager will be visible in the nmap scan to try to conduct the Web Mass Assignment exploitation (or other similar applications like Asset manager). 1. In our case, it is on port 3000. 2. Checking the app.py source code, we can clearly see that the parameter name that needs
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: The Internets role in sanctions enforcement

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-915`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** The Internet’s role in sanctions enforcement Russia/Ukraine and the future Bill Woodcock DEF CON 30 August 12, 2022 As Russia invaded Ukraine in February of this year, the Ukrainian government sent requests to ICANN and RIPE to have Russia removed from the Internet. Those request
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
