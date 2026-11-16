# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-privilege-escalation-uac-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Local Privilege Escalation during execution of VeraCryptExpander.exe (UAC bypass)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Your VeraCryptExpander.exe is vulnerable to a Local Privilege Escalation (UAC BYPASS) during execution. The issue is located here: https://github.com/veracrypt/VeraCrypt/blob/a108db7c85248a3b61d0c89c086922332249f518/src/ExpandVolume/VeraCryptExpander.manifest...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Bypass User Account Control

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Bypass User Account Control **ID**: T1548.002 **Type**: Technique **Tactics**: Privilege Escalation **Platforms**: Windows Adversaries may bypass UAC mechanisms to elevate process privileges on system.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: HTB: Rainbow

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Rainbow] (/img/rainbow-cover.png) Rainbow has a custom Windows executable webserver. I’ll find a crash with some manual fuzzing and use x32dbg to weaponize it to get a shell. The user is in the administrator’s group, but UAC prevents reading the root flag. I’ll abuse the fodhelp
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Enigma Fileless UAC Bypass

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-269`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Enigma Fileless UAC Bypass / EKU-ID: 6208 / CVE: / OSVDB-ID: / / --- / --- / --- / / Author: r00t-3xp10it / Published: 2017-01-10 / 'ruby ## # This file is part of the Metasploit Framework and may be subject to # redistribution and commercial restrictions. Please see the Meta
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: 干货 Bypass Uac 技术总结

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # 一. UAC 用户帐户控制（User Account Control，简写作 UAC)是微软公司在其 Windows Vista 及更高版本操作系统中采用的一种控制机制，保护系统进行不必要的更改，提升操作系统的稳定性和安全性。 管理员在正常情况下是以低权限运行任务的，这个状态被称为被保护的管理员。但当管理员要执行高风险操作（如安装程序等），就需要提升权限去完成这些任务。这个提升权限的过程通常是这样的，相信各位都眼熟过。 点击 “是”，管理员就会提升到高权限再去运行该任务。 # 二. autoElevate 与 requestedExecutionLe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Win10 Bypass Uac

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** # 前言 **有些系统程序在运行时，是不会触发 UAC 的，这类程序都为 "白名单" 程序，而我们就可以使用这类程序来进行 Bypass UAC** 1. 当 **CompMgmtLauncher.exe** 该程序启动时，会查询注册表 **Software\\classes\\mscfile\\shell\\open\\command** 的内容，并执行。 2. 代码实现如下：通过改写注册表即可完成 'cpp #include "stdafx.h" #include #include using nam
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: UAC Bypass via ICMLuaUtil

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-269`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # UAC Bypass via ICMLuaUtil Detects the pattern of UAC Bypass using ICMLuaUtil Elevated COM interface - **Level**: N/A - **Status**: test - **Author**: Florian Roth (Nextron Systems), Elastic (idea) - **Date**: 2022-09-13 - **Category**: Windows ## Rule 'yaml title: UAC Bypass
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: UAC Bypass Tools Using ComputerDefaults

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-269`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # UAC Bypass Tools Using ComputerDefaults Detects tools such as UACMe used to bypass UAC with computerdefaults.exe (UACMe 59) - **Level**: N/A - **Status**: test - **Author**: Christian Burkard (Nextron Systems) - **Date**: 2021-08-31 - **Category**: Windows ## Rule 'yaml title
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
