# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`entra-id-and-hybrid-identity`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Race Conditions in OAuth 2 API implementations

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Most of OAuth 2 API implementations seem to have multiple Race Condition vulnerabilities for processing requests for Access Token or Refresh Token.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Hybrid Identity

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Hybrid Identity **ID**: T1556.007 **Type**: Technique **Tactics**: defense-impairment, Persistence, Credential Access **Platforms**: IaaS, Identity Provider, Office Suite, SaaS, Windows Adversaries may patch, modify, or otherwise backdoor cloud authentication processes that are tied to on-premises...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Hybrid Identity Miscellaneous Attacks

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Hybrid Identity Miscellaneous Attacks Forcing Synchronization of Entra ID users to on-prem As mentioned in https://www.youtube.com/watch?v=JEIR5oGCwdg, it was possible to change the value of **'ProxyAddress'** inside an AD user in the on-prem AD adding the email of an Entra ID admin user and also...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Az - Primary Refresh Token (PRT)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Az - Primary Refresh Token (PRT) What is a Primary Refresh Token (PRT)? A **Primary Refresh Token (PRT)** is a long-lived refresh token used in Azure AD (Entra ID) authentication, analogous to a Kerberos TGT.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Az - Primary Refresh Token (PRT)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-287`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Az - Primary Refresh Token (PRT) ## What is a Primary Refresh Token (PRT)? A **Primary Refresh Token (PRT)** is a long-lived refresh token used in Azure AD (Entra ID) authentication, analogous to a Kerberos TGT. It is issued upon user login on an Azure AD-joined device and can
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Azure AD Application 与 Service Principal 滥用详解

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-287`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # Azure AD Application 与 Service Principal 滥用详解 ## 核心概念 'text App Registration vs Service Principal: ├─ App Registration (应用注册) │ ├─ 应用的"模板"定义（全局唯一 Application ID） │ ├─ 定义所需权限、回调 URL、密钥/证书 │ ├─ 属于创建它的租户 │ └─ 一个 App Registration 可在多个租户中有 Service Principal │ ├─ Service Principal
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Az - PTA - Pass-through Authentication

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-287`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Az - PTA - Pass-through Authentication ## Basic Information [From the docs:] (https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-pta) Microsoft Entra pass-through authentication allows your users to **sign in to both on-premises and cloud-based applic
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Signal K Server vulnerable to JWT Token Theft via WebSocket Enumeration and Unauthenticated Polling

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-287`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Signal K Server vulnerable to JWT Token Theft via WebSocket Enumeration and Unauthenticated Polling - **OSV ID**: GHSA-fq56-hvg6-wvm5 - **CVE**: CVE-2025-68620 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N - **Published**: 2026-01-02T15:28:54Z - **Modified**: 2026-02
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
