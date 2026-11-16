# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`xxe-parser-differential-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: librsvg XInclude 文件包含漏洞 CVE-2023-38633

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-611`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # librsvg XInclude 文件包含漏洞 CVE-2023-38633 ## 漏洞描述 librsvg是一个用于处理SVG图片的开源依赖库。 librsvg支持XML中的XInclude规范，可以用于加载外部内容。在librsvg 2.56.3版本以前，由于处理路径存在逻辑错误，导致攻击者可以传入一个恶意构造的SVG图片，进而读取到任意文件。 参考链接： - https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/ - https://git
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Librsvg XInclude Arbitrary file reading (CVE-2023-38633)

- **Provenance:** Source: `CYBER_CPT/vulhub` | CWE: `CWE-611`
- **Context / Surface:** Source: vulhub (en)
- **Root Cause / Analysis:** # Librsvg XInclude Arbitrary file reading (CVE-2023-38633) Librsvg is a free software SVG rendering library written as part of the GNOME project, intended to be lightweight and portable. A directory traversal problem in the URL decoder of librsvg before 2.56.3 could be used by lo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: windows

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-611`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # windows / - **Template ID**: xinclude-injection - **Severity**: high - **Author**: DhiyaneshDK,ritikchaddha - **Category**: Dast - **Tags**: dast, xxe, xinclude, vuln 'yaml id: xinclude-injection info: name: XInclude Injection - Detection author: DhiyaneshDK,ritikchaddha seve
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: An issue was discovered in libxml2 before 2.11.7 and 2.12.x before 2.12.5. When using the XML Reader

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-611`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in libxml2 before 2.11.7 and 2.12.x before 2.12.5. When using the XML Reader interface with DTD validation and XInclude expansion enabled, processing crafted XML documents can - **CVE**: CVE-2024-25062 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: 浅析xml之xinclude & xslt-安全KER - 安全资讯平台

- **Provenance:** Source: `CYBER_CPT/govuln` | CWE: `CWE-611`
- **Context / Surface:** Source: govuln (en)
- **Root Cause / Analysis:** 首页 阅读 活动 社区 学院 安全导航 内容精选 浅析xml之xinclude & xslt 阅读量 684418 / 评论 2 / 发布时间 : 2018-08-17 16:30:47 前言 最近依旧在研究xml及其相关安全问题，前一篇文章已经提及了较为大众且CTF中常见的xml攻击方式 https://www.anquanke.com/post/id/155328 这里再提两个较为小众的攻击方式（此处小众是指CTF比赛中不常见） Xinclude 什么是xinclude 顾名思义，xinclude可以理解为xml include 熟悉编译/脚本语言的
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: 浅析xml之xinclude & xslt-安全KER - 安全资讯平台

- **Provenance:** Source: `CYBER_CPT/secwiki` | CWE: `CWE-611`
- **Context / Surface:** Source: secwiki (en)
- **Root Cause / Analysis:** 首页 阅读 * [安全资讯] (https://www.anquanke.com/news) * [安全知识] (https://www.anquanke.com/knowledge) * [安全工具] (https://www.anquanke.com/tool) 活动 社区 学院 安全导航 内容精选 * [专栏] (/column/index.html) * [精选专题] (https://www.anquanke.com/subject-list) * [安全KER季刊] (https://www.anquanke.com/discovery) * [360网
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
