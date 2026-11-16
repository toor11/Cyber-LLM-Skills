# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`password-hashing-and-kdf-attacks`](SKILL.md) | Family: **Cryptography Attacks**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Eighteen

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-916`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Eighteen is a Windows Server 2025 assume-breach box starting with MSSQL credentials. I'll use MSSQL login impersonation to access the financial planner database and recover a Werkzeug PBKDF2 hash for the web admin. After cracking the hash and spraying the password against domain
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB Sherlock: Einladen

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-916`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Einladen starts with a ton of artifacts. I’ll work through a phishing HTML page that downloads a Zip with an HTA that creates three executables and a PDF, then runs one of the executables. The one it runs is a legit Microsoft binary, but the DLLs are malware, side-loaded by the l
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: 深入分析 Saltstack Salt 命令注入漏洞

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-916`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** 一、概述 11 月 3 日，SaltStack 发布了 Salt 的安全补丁，修复了三个高危漏洞。其中有两个修复程序，是为了解决外部研究人员通过 ZDI 项目提交的五个漏洞。这些漏洞可导致在运行 Salt 应用程序的系统上实现未经身份验证的命令注入。ZDI-CAN-11143 是由一位匿名研究人员提交给 ZDI 的，而其余的漏洞则是我们发现的 ZDI-CAN-11143 的变体。在这篇文章中，我们将详细研究这些漏洞的根本原因。 二、漏洞详情 漏洞影响应用程序的 rest-cherrypy netapi 模块。rest-cherrypy 模块为 Salt
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: 在有 salt-call 权限的系统上执行：

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-916`
- **Context / Surface:** Source: github_security_md (zh)
- **Root Cause / Analysis:** # CVE-2021-31607: SaltStack Minion Snapper 命令注入漏洞 **影响版本:** SaltStack Salt 2016.9 - 3002.6 **严重性:** MEDIUM **标签:** command_injection, 需要认证 ## 漏洞描述 SaltStack Salt 的 Snapper 模块在处理文件名时，未对参数进行安全过滤即直接拼接到 shell 命令中。拥有 Salt minion 调用权限的攻击者可通过构造包含 shell 元字符的文件名实现命令注入。该漏洞属于本地权限提升漏洞，需要已认证的
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: crypto-es PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standa

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-916`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # crypto-es PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard - **OSV ID**: GHSA-mpj8-q39x-wq5h - **CVE**: CVE-2023-46133 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N - **Published**: 2023-10-25T21:14:44Z - **Modified**: 2023
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Instant

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-916`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Instant] (/img/instant-cover.png) Instant starts with an Android application. In reversing it, I’ll find a domain for the API swagger documentation, as well as a hard-coded admin JWT token. I’ll use that token to access the admin API, where I’ll find a file read vulnerability th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
