# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sql-injection-mssql-variants`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: MSSQL Injection

- **Provenance:** Source: `CYBER_CPT/payloads_all_the_things` | CWE: `CWE-89`
- **Context / Surface:** Source: payloads_all_the_things (en)
- **Root Cause / Analysis:** # MSSQL Injection > MSSQL Injection is a type of security vulnerability that can occur when an attacker can insert or "inject" malicious SQL code into a query executed by a Microsoft SQL Server (MSSQL) database. This typically happens when user inputs are directly included in SQL
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: xp_cmdshell

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-89`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # xp_cmdshell * Disabled by default since SQL Server 2005 * Executed with the privileges of SQL Server service account * Synchronous * 'sysadmin' privileges are required If uninstalled: 'sql sp_addextendedproc 'xp_cmdshell','xplog70.dll' ' If disabled: 'sql EXEC sp_configur
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: MSSQL Injection

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-89`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # MSSQL Injection ## Active Directory enumeration It may be possible to **enumerate domain users via SQL injection inside a MSSQL** server using the following MSSQL functions: - **'SELECT DEFAULT_DOMAIN()'**: Get current domain name. - **'master.dbo.fn_varbintohexstr(SUSER_SID('D
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Full MSSQL Injection PWNage

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-89`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Remote code execution via web shell upload / Dec 16, 2022 ## Introduction Welcome to my another writeup! In this Portswigger Labs lab, you'll learn: Remote code execution via web shell upload! Without further ado, let's dive in. - Overall difficulty for me (From 1-10 stars): ★☆
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Signed

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-89`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Signed] (/img/signed-cover.png) Signed is an assume breach Windows box where I’m given credentials for a local MSSQL account. I’ll enumerate the database, coerce authentication from the MSSQL service account using xp\_dirtree, and crack the NetNTLMv2 hash. With the service accou
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
