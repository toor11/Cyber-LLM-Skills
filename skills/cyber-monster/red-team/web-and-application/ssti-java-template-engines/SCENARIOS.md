# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssti-java-template-engines`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Thymeleaf ssti 3.1.2 黑名单绕过 - wh1t3p1g's blog

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** 跳转至 wh1t3p1g's blog Thymeleaf ssti 3.1.2 黑名单绕过 键入以开始搜索 GitHub Home Blog Writeups About Me Blog 2024 Thymeleaf ssti 3.1.2 黑名单绕过 2023 2021 2020 2019 2018 2017 2016 目录 0x01 前言 0x02 简述 ChatterBox 解题思路 0x03 thymeleaf 沙盒原理 类型限制 函数调用限制 0x04 如何绕过这两个限制 编写 Cypher 语句 结果确认 思路一：反射构造函数 思路二：反射函数调用 0x05 总结 Java...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: FreeMarker SSTI 执行命令

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-1336`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** --- id: CVE-2018-16341 title: Nuxeo Platform SSTI 远程代码执行（CVE-2018-16341） product: nuxeo vendor: Nuxeo version_affected: "< 10.3" severity: CRITICAL tags: [rce, ssti, 无需认证] fingerprint: ["Nuxeo"] --- ## 漏洞描述 Nuxeo Platform 在处理错误页面时存在服务器端模板注入（SSTI）漏洞。通过访问不存在的页面并在 URL 中注入 FreeMarker
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Localization is hard

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-1336`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # CTF — Cyberseg 2018 (Crypto/Stego) Unos pequeños writeups acerca de los retos de crypto/stego de la Cyberseg 2018 en España. # El dado fue echado (50pts) ## Solución Para la solución de este reto se identifico que el texto fue cifrado usando “Caesar Cipher”, por lo que se uso e
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: CVE-2022-22954 VMware Workspace ONE Access freemarker SSTI 漏洞 命令执行、批量检测脚本、文件写入

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-1336`
- **Context / Surface:** Source: go_exploitdb (mixed)
- **Root Cause / Analysis:** # CVE-2022-22954 VMware Workspace ONE Access freemarker SSTI 漏洞 命令执行、批量检测脚本、文件写入 - **CVE**: CVE-2022-22954 - **Exploit Type**: GitHub - **Exploit ID**: GitHub-fe64e200fdf0dfc6236fece7c6f8d21b - **URL**: https://github.com/bewhale/CVE-2022-22954 - **GitHub Stars**: 70 - **GitHub F
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Multiple cross-site scripting (XSS) vulnerabilities in component handlers in the javatemplates (aka

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-1336`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Multiple cross-site scripting (XSS) vulnerabilities in component handlers in the javatemplates (aka Java Templates) plugin in Apache Struts 2.x before 2.2.3 allow remote attackers to inject arbitrary - **CVE**: CVE-2011-2087 - **Exploit Type**: InTheWild - **Exploit ID**: InThe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Apache StreamPark: FreeMarker SSTI RCE Vulnerability

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1336`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** On versions before 2.1.4, a user could log in and perform a template injection attack resulting in Remote Code Execution on the server, The attacker must successfully log into the system to launch an attack, so this is a moderate-impact vulnerability. Mitigation: all users should
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: JDK 17+ FreeMarker SSTI：从 CVE-2023-4450 复现引出 MethodHandle 句柄、named module 机制研究 🦖 Whoopsunix

- **Provenance:** Source: `CYBER_CPT/govuln` | CWE: `CWE-1336`
- **Context / Surface:** Source: govuln (en)
- **Root Cause / Analysis:** Skip to main content Whoopsunix WIKI Blog Tag GitHub 时间线 PPPYSO Java 安全 表达式注入 SAST 之路 JDK 17+ FreeMarker SSTI：从 CVE-2023-4450 复现引出 MethodHandle 句柄、named module 机制研究 RASP 组件漏洞分析 RT Attack DevOps Attack Java 安全JDK 17+ FreeMarker SSTI：从 CVE-2023-4450 复现引出 MethodHandle 句柄、named modul
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
