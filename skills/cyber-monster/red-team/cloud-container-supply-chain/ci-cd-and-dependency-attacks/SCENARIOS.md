# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ci-cd-and-dependency-attacks`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: WordPress Plugin Update Confusion at trafficfactory.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I'm currently researching a "novel" supply chain attack affecting WordPress plugins, and I believe your website might be vulnerable. The way it works is similar to a recent Dependency Confusion attack, where a malicious actor can take over internal packages unclaimed on PyPI...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Turning Dependency Confusion Research into a Profitable Stack

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** Skip to main content Hashnode >_ sl4x0 security research Open search (press Control or Command and K) Toggle theme Write Command Palette Search for a command to run...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Dependency Confusion

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Dependency Confusion {{#include ../banners/hacktricks-training.md}} Basic Information Dependency Confusion (a.k.a. substitution attacks) happens when a package manager resolves a dependency name from an unintended, less-trusted registry/source (usually a public registry) instead of the intended...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: GCP - Artifact Registry Persistence

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** GCP - Artifact Registry Persistence Artifact Registry For more information about Artifact Registry check: ../gcp-services/gcp-artifact-registry-enum.md Dependency Confusion - What happens if a **remote and a standard** repositories **are mixed in a virtual** one and a package exists in both? - The...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Dependency Confusion 详细利用步骤

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-1357`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # Dependency Confusion 详细利用步骤 ## 原理深入 — 包管理器版本优先级机制 'text 核心问题: ├─ 企业使用私有包仓库 + 公共包仓库 ├─ 包管理器需要决定: 从哪个源安装包? ├─ 如果同名包在两个源都存在 → 版本号更高的被安装 ├─ 攻击者在公共源发布同名包（版本号设为极高值） └─ 结果: 企业 CI/CD 或开发者安装了攻击者的恶意包 攻击前提条件: ├─ 1. 目标使用私有包（非 scope/namespace 保护） ├─ 2. 包管理器配置了多源（私有 + 公共） ├─ 3. 私有包名在公共源上未被
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Dependency Confusion

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-1357`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Dependency Confusion {{#include ../banners/hacktricks-training.md}} ## Basic Information Dependency Confusion (a.k.a. substitution attacks) happens when a package manager resolves a dependency name from an unintended, less-trusted registry/source (usually a public registry) ins
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: A dependency confusion in pipreqs v0.3.0 to v0.4.11 allows attackers to execute arbitrary code via u

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-1357`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # A dependency confusion in pipreqs v0.3.0 to v0.4.11 allows attackers to execute arbitrary code via uploading a crafted PyPI package to the chosen repository server. - **CVE**: CVE-2023-31543 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-6bc8a121bd1253edbcfe6c7a60dfe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Antilles Dependency Confusion Vulnerability

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-1357`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Antilles Dependency Confusion Vulnerability Antilles Dependency Confusion Vulnerability - **OSV ID**: GHSA-hgc3-hp6x-wpgx - **CVE**: CVE-2021-3840 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H - **Published**: 2021-11-03T17:36:22Z - **Modified**: 2026-03-13T22:14:14.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
