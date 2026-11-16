# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`code-injection-and-eval-expression-language`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Remote Code Execution (RCE) in a DoD website

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** One of the DoD applications uses a java library which is vulnerable to expression language injection. Using only an URL I was able to inject java code. I made a simple PoC that requests a name resolution to a DNS server.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: EL/SpEL/OGNL/MVEL 深度利用手册

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-94`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # EL/SpEL/OGNL/MVEL 深度利用手册 ## SpEL 高级 Payload 变体 ### 反射链 — 绕过 T() 限制 当 'SimpleEvaluationContext' 禁用 'T()' 操作符时，通过字符串反射链到达 Runtime： 'java #{'.class.forName('java.lang.Runtime').getMethod('exec','.class).invoke('.class.forName('java.lang.Runtime').getMethod('getRuntime').invok
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - 'Jakarta' Multipart Parser OGNL Injection (Metasploit)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-94`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Apache Struts 2.3.5 < 2.3.31 / 2.5 < 2.5.10 - 'Jakarta' Multipart Parser OGNL Injection (Metasploit) / EKU-ID: 45821 / CVE: CVE-2017-5638 / OSVDB-ID: / / --- / --- / --- / / Author: Metasploit / Published: 2017-03-15 / Verified: / 'ruby ## # This module requires Metasploit: h
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Apache Struts 2 Namespace Redirect OGNL Injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-94`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Apache Struts 2 Namespace Redirect OGNL Injection / / / / / --- / --- / --- / / EKU-ID: 7933 / CVE: [2018-11776] (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-11776) / OSVDB-ID: / / Author: wvu / Published: 2018-09-10 / Verified: / 'ruby ## # This module requires Met
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Apache Unomi Expression Language Injection RCE (CVE-2020-13942)

- **Provenance:** Source: `CYBER_CPT/vulhub` | CWE: `CWE-94`
- **Context / Surface:** Source: vulhub (en)
- **Root Cause / Analysis:** # Apache Unomi Expression Language Injection RCE (CVE-2020-13942) Apache Unomi is a Java Open Source customer data platform, a Java server designed to manage customers, leads and visitors’ data and help personalize customers experiences. In the versions prior to 1.5.1, Apache Uno
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: OpenMetadata vulnerable to a SpEL Injection in 'GET /api/v1/policies/validation/condition/' ('

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-94`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # OpenMetadata vulnerable to a SpEL Injection in 'GET /api/v1/policies/validation/condition/' ('GHSL-2023-236') - **OSV ID**: GHSA-5xv3-fm7g-865r - **CVE**: CVE-2024-28848 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H - **Published**: 2024-04-24T17:06:02Z - **Mod
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: OpenMetadata vulnerable to SpEL Injection in 'PUT /api/v1/policies' ('GHSL-2023-252')

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-94`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # OpenMetadata vulnerable to SpEL Injection in 'PUT /api/v1/policies' ('GHSL-2023-252') - **OSV ID**: GHSA-7vf4-x5m2-r6gr - **CVE**: CVE-2024-28253 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L - **Published**: 2024-04-23T21:11:23Z - **Modified**: 2025-09-04T16:45:40.6
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
