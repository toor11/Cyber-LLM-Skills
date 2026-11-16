# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`edr-evasion-and-amsi-bypass-etw-and-telemetry-evasion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: APT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-693`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** APT was a clinic in finding little things to exploit in a Windows host. I’ll start with access to only RPC and HTTP, and the website has nothing interesting. I’ll use RPC to identify an IPv6 address, which when scanned, shows typical Windows DC ports. Over SMB, I’ll pull a zip co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Windows - AMSI Bypass

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Windows - AMSI Bypass ## List AMSI Providers * List providers with : 'Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\' * Find software from CLSID 'ps1 Get-ChildItem -Path 'HKLM:\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}' Name Property ---- -
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: 手工绕过 Amsi 第二部分 Invoke Mimikatz 先知社区

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** 这篇博客文章将讲一些关于 AMSI 更深层的触发器。我决定构建一个没有 AMSI 触发器的定制 Invoke-Mimikatz 脚本。我还将介绍一些关于 Invoke-Mimikatz 的工作原理。 ### 0x00 介绍 如果阅读了我的上一篇博客文章，[通过手动修改绕过 AMSI] (https://s3cur3th1ssh1t.github.io/Bypass_AMSI_by_manual_modification/)，可能已经想到了要为'Invoke-Mimikatz' 或 'Sharphound' 寻找触发器，并构建自己的未被 AMSI 检测的版本
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: DEFCON-27-Workshop-Anthony-Rose-Introduction-to-AMSI-Bypasses-and-Sandbox-Evasion

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-693`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** ANTHONY ROSE JACOB KRASNOV VINCENT ROSE @bcsecurity1 Legal Stuff…So we don’t go to jail Training is for informational and research purposes only. We believe that ethical hacking, information security and cyber security should be familiar subjects to anyone using digital informati
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Mist

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-693`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Mist] (/img/mist-cover.png) Mist is an insane-level Windows box mostly focused on Active Directory attacks. It starts off with a simple file disclosure vulneraility in Pluck CMS that allows me to leak the admin password and upload a malicious Pluck module to get a foothold on th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
