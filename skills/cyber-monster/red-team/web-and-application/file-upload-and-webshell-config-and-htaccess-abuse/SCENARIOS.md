# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`file-upload-and-webshell-config-and-htaccess-abuse`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Perspective

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-434`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Perspective is all about exploiting a ASP.NET application in many different ways. I'll start by uploading a SHTML file that allows me to read the configuration file for the application. With that, I'll leak one of the keys used by the application, and the fact that there are more
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Fulcrum

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-434`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Fulcrum is a 2017 release that got a rebuild in 2022. It’s a Linux server with four websites, including one that returns Windows .NET error messages. I’ll exploit an API endpoint via XXE, and use that as an SSRF to get execution through a remote file include. From there I’ll pivo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB Endgame: P.O.O.

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-434`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Endgame Professional Offensive Operations (P.O.O.) was the first Endgame lab released by HTB. Endgame labs require at least Guru status to attempt (though now that P.O.O. is retired, it is available to all VIP). The lab contains two Windows hosts, and I'm given a single IP that r
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: 读取 web.config

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-434`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** ## 漏洞描述 金和OA C6 的 download.asp 文件存在任意文件读取漏洞，filename 参数接受任意路径作为输入，攻击者无需认证即可通过路径穿越读取服务器上的 web.config 等敏感配置文件。 ## 影响版本 - 金和OA C6 ## 前置条件 - 无需认证 - 目标运行金和OA C6 ## 利用步骤 1. 确认目标为金和OA 2. 通过 download.asp 的 filename 参数读取文件 3. 下载 web.config 获取数据库连接信息 ## Payload 'bash # 读取 web.config curl
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: 读取 web.config

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-434`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # HONGFAN-FILE-READ: 红帆OA ioffice ioFileExport.aspx 任意文件读取漏洞 **Product:** hongfan-oa **Vendor:** 红帆科技 **Version Affected:** all versions **Severity:** HIGH **Tags:** file_read, 无需认证, 国产, oa **Fingerprint:** 红帆, ioffice ## 漏洞描述 红帆OA（ioffice）的 ioFileExport.aspx 文件存在任意文件读取漏洞，url 参数直
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: 读取 web.config

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-434`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** id: SMARTOA-FILE-READ title: 智明SmartOA EmailDownload.ashx 任意文件下载漏洞 product: smartoa vendor: 智明协同 version_affected: "all versions" severity: HIGH tags: [file_read, path_traversal, 无需认证, 国产, oa] fingerprint: ["SmartOA", "智明协同"] ## 漏洞描述 智明 SmartOA 的 EmailDownload.ashx 文件存在任意文件下载漏洞，u
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
