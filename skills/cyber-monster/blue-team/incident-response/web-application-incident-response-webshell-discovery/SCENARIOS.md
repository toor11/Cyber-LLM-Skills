# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-application-incident-response-webshell-discovery`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: File Integrity Monitoring

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** File Integrity Monitoring {{#include ../../banners/hacktricks-training.md}} Baseline A baseline consists of taking a snapshot of certain parts of a system to **compare it with a future status to highlight changes**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: PsiTransfer: File integrity violation

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary The absence of restrictions on the endpoint, which is designed for uploading files, allows an attacker who received the id of a file distribution to change the files that are in this distribution. ### Details Vulnerable endpoint: PATCH /files/{{id}} ### PoC 1. Create
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: File Integrity Monitoring

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-778`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # File Integrity Monitoring {{#include ../../banners/hacktricks-training.md}} ## Baseline A baseline consists of taking a snapshot of certain parts of a system to **compare it with a future status to highlight changes**. For example, you can calculate and store the hash of each f
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: PsiTransfer: File integrity violation

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # PsiTransfer: File integrity violation - **OSV ID**: GHSA-2p2x-p7wj-j5h2 - **CVE**: CVE-2024-31454 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N - **Published**: 2024-04-05T17:15:27Z - **Modified**: 2024-04-10T19:11:43.870211Z - **Affected Packages**: psitransfer - **
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Introducing Hybrid File Integrity Monitoring

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-778`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** Runtime File Integrity Monitoring (FIM) has been added to the existing agentless solution, creating a hybrid approach. This provides comprehensive visibility and deep context to enable accurate and effective monitoring of critical files across environments. # What is FIM? File In
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Mids' Reborn Hero Designer 2.6.0.7 downloads the update manifest, as well as update files, over clea

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Mids' Reborn Hero Designer 2.6.0.7 downloads the update manifest, as well as update files, over cleartext HTTP. Additionally, the application does not perform file integrity validation for files after - **CVE**: CVE-2020-11614 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: 开源日志关联系统 opensource log Correlation_logalyze安装-CSDN博客

- **Provenance:** Source: `CYBER_CPT/secwiki` | CWE: `CWE-778`
- **Context / Surface:** Source: secwiki (en)
- **Root Cause / Analysis:** # 开源日志关联系统 opensource log Correlation 最新推荐文章于 2026-02-18 03:56:11 发布 原创 最新推荐文章于 2026-02-18 03:56:11 发布 · 3.6k 阅读 · ![] (https://csdnimg.cn/release/blogv2/dist/pc/img/newHeart2023Active.png) ![] (https://csdnimg.cn/release/blogv2/dist/pc/img/newHeart2023Black.png) 0 · ![] (https://cs
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
