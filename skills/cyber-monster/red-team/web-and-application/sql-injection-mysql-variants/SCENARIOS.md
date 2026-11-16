# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sql-injection-mysql-variants`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: MySQL Injection

- **Provenance:** Source: `CYBER_CPT/payloads_all_the_things` | CWE: `CWE-89`
- **Context / Surface:** Source: payloads_all_the_things (en)
- **Root Cause / Analysis:** # MySQL Injection > MySQL Injection is a type of security vulnerability that occurs when an attacker is able to manipulate the SQL queries made to a MySQL database by injecting malicious input. This vulnerability is often the result of improperly handling user input, allowing att
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: PHP Director 0.21 - SQL Into Outfile 'eval()' Injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-89`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # picoCTF 2024: dont-you-love-banners ![\\"Altair\\"] (\\"https://miro.medium.com/v2/da:true/resize:fill:88:88/0*Vt- nLzWCRL8oUGg5\\") Altair · Follow 4 min read · Mar 26, 2024 \-- 2 Listen Share Tags: General Skills, browser_webshell_solvable, shell ## Description Can you abuse t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: MySQL >= 5.6.35 AND Error based - extractvalue,updatexml

- **Provenance:** Source: `CYBER_CPT/exploitdb` | CWE: `CWE-89`
- **Context / Surface:** Source: exploitdb (en)
- **Root Cause / Analysis:** # MySQL >= 5.6.35 AND Error based - extractvalue,updatexml SOA School Management - 'access_login' SQL Injection - **ExploitDB ID**: 44037 - **Author**: L0RD - **Date**: 2018-02-14 - **Platform**: php - **Type**: webapps - **URL**: https://www.exploit-db.com/exploits/44037
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: OTCMS v3.85 allows arbitrary PHP Code Execution because admin/sysCheckFile_deal.php blocks "into out

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-89`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # OTCMS v3.85 allows arbitrary PHP Code Execution because admin/sysCheckFile_deal.php blocks "into outfile" in a SELECT statement, but does not block the "into/**/outfile" manipulation. Therefore, the attacker can create a .php file. - **CVE**: CVE-2019-17370 - **Exploit Type**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: The id parameter in view_storage.php from Simple Cold Storage Management System 1.0 appears to be vu

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-89`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # The id parameter in view_storage.php from Simple Cold Storage Management System 1.0 appears to be vulnerable to SQL injection attacks. A payload injects a SQL sub-query that calls MySQL's load_file fu - **CVE**: CVE-2021-45253 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: The id parameter from Online Enrollment Management System 1.0 system appears to be vulnerable to SQL

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-89`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # The id parameter from Online Enrollment Management System 1.0 system appears to be vulnerable to SQL injection attacks. A crafted payload injects a SQL sub-query that calls MySQL's load_file function - **CVE**: CVE-2021-44599 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
