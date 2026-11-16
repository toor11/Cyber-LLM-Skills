# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`xml-attacks-xxe-and-xslt-xpath-and-schema`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: XPATH injection

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-611`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # XPATH injection ## Basic Syntax An attack technique known as XPath Injection is utilized to take advantage of applications that form XPath (XML Path Language) queries based on user input to query or navigate XML documents. ### Nodes Described Expressions are used to select vari
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: xpath injection

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-611`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # xpath injection ## Detection method To find this vulnerabilities sends the string "d'z'0" to every injection point, and searches the response for XPATH errors ### Basic Payloads ' d'z"0 <!--" ' ##### Regexp for error ' System\.Xml\.XPath\.XPathException/MS\.Internal\.Xml/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: librsvg XInclude 文件包含漏洞 CVE-2023-38633

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-611`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # librsvg XInclude 文件包含漏洞 CVE-2023-38633 ## 漏洞描述 librsvg是一个用于处理SVG图片的开源依赖库。 librsvg支持XML中的XInclude规范，可以用于加载外部内容。在librsvg 2.56.3版本以前，由于处理路径存在逻辑错误，导致攻击者可以传入一个恶意构造的SVG图片，进而读取到任意文件。 参考链接： - https://www.canva.dev/blog/engineering/when-url-parsers-disagree-cve-2023-38633/ - https://git
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: xsd

- **Provenance:** Source: `CYBER_CPT/lolbas` | CWE: `CWE-611`
- **Context / Surface:** Source: lolbas (en)
- **Root Cause / Analysis:** XML Schema Definition Tool included with the Windows Software Development Kit (SDK). ### Paths: * C:\Program Files (x86)\Microsoft SDKs\Windows\\bin\NETFX Tools\xsd.exe ### Detections: * IOC: URL on a xsd.exe command line * IOC: xsd.exe making unexpected networ
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: XPath Injection

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-611`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **XPath Injection** is a vulnerability where user input is incorporated into XPath queries without proper sanitization, allowing attackers to manipulate queries to access unauthorized data from XML documents. ### How It Works XPath is a query language for selecting nodes from XML
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Concrete5 CME v9.1.3 - Xpath injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-611`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Concrete5 CME v9.1.3 - Xpath injection / / / / / --- / --- / --- / / EKU-ID: 55038 / CVE: / OSVDB-ID: / / Author: nu11secur1ty / Published: 2023-03-30 / Verified: ![Not Verified] (/images/cancel.png) / / Download: / / / / / / --- / / Rating☆☆☆☆☆ / [![] (/images/prev.png)] (/local/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
