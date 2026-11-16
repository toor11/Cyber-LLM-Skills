# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`aws-attacks-compute-and-metadata`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: How to leverage generative AI in cloud apps without putting user data at risk

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-269`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** # TL;DR 1. Given the rapid advancements in generative AI (GenAI) over the past year, many organizations are beginning to develop solutions utilizing GenAI solutions such as large language models (LLMs) 2. As developers begin to incorporate GenAI models as part of their cloud apps
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Paperclip: Malicious skills able to exfiltrate and destroy all user data

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary An arbitrary code execution vulnerability in the workspace runtime service allows any agent to execute shell commands on the server, exposing all environment variables including API keys, JWT secrets, and database credentials. ### Details A malicious skill can instruc
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: AVideo Allows Unauthenticated Access to AD_Server reports.json.php that Exposes Ad Campaign Analytic

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The 'plugin/AD_Server/reports.json.php' endpoint performs no authentication or authorization checks, allowing any unauthenticated attacker to extract ad campaign analytics data including video titles, user channel names, user IDs, ad campaign names, and impression/clic
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: User Data

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (zh)
- **Root Cause / Analysis:** # 使用用户数据执行命令 ## 前言 在创建云服务器时，用户可以通过指定自定义数据，进行配置实例，当云服务器启动时，自定义数据将以文本的方式传递到云服务器中，并执行该文本，而且文本里的命令默认以 root 权限执行。 通过这一功能，攻击者可以修改实例的用户数据并向其中写入待执行的命令，这些代码将会在实例每次启动时自动执行。 ## 控制台 在控制台界面可以直接编辑实例的用户数据。 在 AWS 下，修改用户数据需要停止实例，在 AWS 下停止实例会擦除实例存储卷上的所有数据，如果没设置弹性 IP，实例的公有 IP 也会变化，因此停止实例需谨慎。 修改用户数据
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Paperclip: Malicious skills able to exfiltrate and destroy all user data

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-269`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Paperclip: Malicious skills able to exfiltrate and destroy all user data Paperclip: Malicious skills able to exfiltrate and destroy all user data - **OSV ID**: GHSA-w8hx-hqjv-vjcq - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N - **Published**: 2026-04-16T22:46:52Z - *
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: AI-Powered App Exposes User Data, Creates Risk of Supply Chain Attacks

- **Provenance:** Source: `CYBER_CPT/trend_micro_research` | CWE: `CWE-269`
- **Context / Surface:** Source: trend_micro_research (en)
- **Root Cause / Analysis:** # AI-Powered App Exposes User Data, Creates Risk of Supply Chain Attacks Trend™ Research’s analysis of Wondershare RepairIt reveals how the AI-driven app exposed sensitive user data due to unsecure cloud storage practices and hardcoded credentials, creating risks of model tamperi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
