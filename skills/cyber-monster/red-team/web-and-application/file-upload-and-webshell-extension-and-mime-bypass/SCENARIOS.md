# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`file-upload-and-webshell-extension-and-mime-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Double File Extension

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Double File Extension **ID**: T1036.007 **Type**: Technique **Tactics**: stealth **Platforms**: Windows Adversaries may abuse a double extension in the filename as a means of masquerading the true file type.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: 检查 shell.php 是否写入成功

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-434`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** --- id: THINKPHP-LANG-RCE title: ThinkPHP 多语言本地文件包含漏洞 product: thinkphp vendor: ThinkPHP version_affected: "<= 6.0.13" severity: CRITICAL tags: [rce, lfi, 无需认证] fingerprint: ["ThinkPHP", "ThinkPHP 6.x"] --- ## 漏洞描述 ThinkPHP 在其 6.0.13 版本及以前，存在一处本地文件包含漏洞。当多语言特性被开启时，攻击者可以使用 'lang' 参
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: 检查 shell.php 是否被创建

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-434`
- **Context / Surface:** Source: github_security_md (zh)
- **Root Cause / Analysis:** --- id: CVE-2024-2961 title: PHP利用GNU C Iconv将文件读取变成RCE（CVE-2024-2961） product: php vendor: PHP/GNU version_affected: "iconv<2.39" severity: CRITICAL tags: [rce, file_read, 无需认证] fingerprint: ["PHP"] --- ## 漏洞描述 GNU C 的 'iconv()' 函数 2.39及以前存在一处缓冲区溢出漏洞。如果一个PHP应用中存在任意文件读取漏洞，攻击者可以利用
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Suspicious Double Extension File Execution

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-434`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Suspicious Double Extension File Execution Detects suspicious use of an .exe extension after a non-executable file extension like .pdf.exe, a set of spaces or underlines to cloak the executable file in spear phishing campaigns - **Level**: N/A - **Status**: stable - **Author**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Suspicious LNK Double Extension File Created

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-434`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Suspicious LNK Double Extension File Created - **Level**: N/A - **Status**: test - **Author**: Nasreddine Bencherchali (Nextron Systems), frack113 - **Date**: 2022-11-07 - **Category**: Windows ## Rule 'yaml title: Suspicious LNK Double Extension File Created id: 3215aa19-f06
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Suspicious Double Extension Files

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-434`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Suspicious Double Extension Files Detects dropped files with double extensions, which is often used by malware as a method to abuse the fact that Windows hide default extensions by default. - **Level**: N/A - **Status**: test - **Author**: Nasreddine Bencherchali (Nextron Syste
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Unrestricted file upload vulnerability in sitex allows remote attackers to upload arbitrary PHP code

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-434`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Unrestricted file upload vulnerability in sitex allows remote attackers to upload arbitrary PHP code via an avatar filename with a double extension such as .php.jpg, which fails verification and is sa - **CVE**: CVE-2007-1235 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
