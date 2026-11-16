# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`insecure-deserialization-php-gadgets`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: RCE via Local File Read -> php unserialization-> XXE -> unpickling

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** It was possible to escalate to Remote Code Execution via different bugs such as local file read, php object injection, XML External Entity and Un-Pickling of Python serialized object.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Hack The Box — Tenet Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Hack The Box — Tenet Writeup > TL;DR A comment in the blog’s Migration part leads you to an endpoint that is vulnerable to PHP Object Injection. After successfully injecting a malicious object and obtaining a shell, you can escalate to the user by reusing the MYSQL credentials found in the WordPress config file.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: HTB: CyberMonday

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** CyberMonday is a crazy difficult box, most of it front-loaded before the user flag. I'll start with a website, and abuse an off-by-slash nginx misconfiguration to read a .env file and the Git source repo. I'll find a mass assignment vulnerability in the site allowing me to get ad
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Horizontall

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Horizontall was built around vulnerabilities in two web frameworks. First there’s discovering an instance of strapi, where I’ll abuse a CVE to reset the administrator’s password, and then use an authenticated command injection vulnerability to get a shell. With a foothold on the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: PHP Deserialization

- **Provenance:** Source: `CYBER_CPT/payloads_all_the_things` | CWE: `CWE-502`
- **Context / Surface:** Source: payloads_all_the_things (en)
- **Root Cause / Analysis:** # PHP Deserialization > PHP Object Injection is an application level vulnerability that could allow an attacker to perform different kinds of malicious attacks, such as Code Injection, SQL Injection, Path Traversal and Application Denial of Service, depending on the context. The
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Zend Framework Pop Chain 先知社区

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-502`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** 在'2020-11-23'号，在'twitter'上看到有师傅发了,'Zend Framework'框架的一条[反序列化链] (https://twitter.com/ptswarm/status/1330878577936625671)。之后也分析了下，找到了几条链子，之后跟了跟其他版本的，都是存在反序列化漏洞的。然后就出了两个题目，一个 最新版的 laminas 和一个 ZendFramework 1 的链子。来写下文章抛砖引玉吧，应该还是有很多的链子的。 ## 1.1 获取源码 & 创建 zf1 项目 [原 pop 链地址] (https://gist
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Catch

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-502`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Catch] (https://0xdfimages.gitlab.io/img/catch-cover.png) Catch requires finding an API token in an Android application, and using that to leak credentials from a chat server. Those credentials provide access to multiple CVEs in a Cachet instance, providing several different pat
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: InvoiceShelf <= 1.3.0 - PHP Deserialization

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-502`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # InvoiceShelf <= 1.3.0 - PHP Deserialization - **Template ID**: CVE-2024-55556 - **Severity**: critical - **Author**: iamnoooob,rootxharsh,pdresearch - **CVE**: CVE-2024-55556 - **Category**: Code - **Tags**: cve, cve2024, invoiceshelf, rce, deserialization, vuln 'yaml id: CVE
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
