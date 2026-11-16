# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`azure-and-entra-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Race Conditions in OAuth 2 API implementations

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Most of OAuth 2 API implementations seem to have multiple Race Condition vulnerabilities for processing requests for Access Token or Refresh Token.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Az - Primary Refresh Token (PRT)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Az - Primary Refresh Token (PRT) ## What is a Primary Refresh Token (PRT)? A **Primary Refresh Token (PRT)** is a long-lived refresh token used in Azure AD (Entra ID) authentication, analogous to a Kerberos TGT. It is issued upon user login on an Azure AD-joined device and can
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Azure AD Application 与 Service Principal 滥用详解

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # Azure AD Application 与 Service Principal 滥用详解 ## 核心概念 'text App Registration vs Service Principal: ├─ App Registration (应用注册) │ ├─ 应用的"模板"定义（全局唯一 Application ID） │ ├─ 定义所需权限、回调 URL、密钥/证书 │ ├─ 属于创建它的租户 │ └─ 一个 App Registration 可在多个租户中有 Service Principal │ ├─ Service Principal
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: RBAC Roles for 'etcd' created by Kamaji are not disjunct

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-269`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # RBAC Roles for 'etcd' created by Kamaji are not disjunct - **OSV ID**: GHSA-6r4j-4rjc-8vw5 - **CVE**: CVE-2024-42480 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N - **Published**: 2024-08-12T18:22:06Z - **Modified**: 2024-11-18T16:27:03Z - **Affected Packages**: gith
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: 基于Azure Service Principal 访问Azure KeyVault

- **Provenance:** Source: `CYBER_CPT/pstips` | CWE: `CWE-269`
- **Context / Surface:** Source: pstips (mixed)
- **Root Cause / Analysis:** # 基于Azure Service Principal 访问Azure KeyVault 在上一篇文章中，我们演示了如何使用Azure 资源托管标识访问KeyVault，但是对于Azure中国区的朋友来说，会空欢喜一场。因为截至本文发稿。Azure资源托管标识功能仍旧未在中国区上线。 所以我们只能使用Azure Service Principal来访问KeyVault了，其中会需要用到一个AAD的ApplicationID和 秘钥。这种场景就比较诡异了，我为了不把某个秘钥写在应用程序中，期望它在运行时，动态的去KeyVault中读取。结果我去和KeyVa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Nhost Leaks Refresh Tokens via URL Query Parameter in OAuth Provider Callback

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Refresh Token Leaked via URL Query Parameter in OAuth Provider Callback ## Summary The auth service's OAuth provider callback flow places the refresh token directly into the redirect URL as a query parameter. Refresh tokens in URLs are logged in browser history, server access l
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: RBAC Roles for 'etcd' created by Kamaji are not disjunct

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary Using an "open at the top" range definition in RBAC for etcd roles leads to some TCPs API servers being able to read, write and delete the data of other control planes. ### Details The problematic code is this: https://github.com/clastix/kamaji/blob/8cdc6191242f80d120
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
