# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-service-and-scheduled-task-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Android Accessibility Service Abuse

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Android Accessibility Service Abuse Overview 'AccessibilityService' was created to help users with disabilities interact with Android devices. Unfortunately, the same **powerful automation APIs** (global navigation, text input, gesture dispatch, overlay windows…) can be weaponised by malware to...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Android Accessibility Service Abuse

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Android Accessibility Service Abuse ## Overview 'AccessibilityService' was created to help users with disabilities interact with Android devices. Unfortunately, the same **powerful automation APIs** (global navigation, text input, gesture dispatch, overlay windows…) can be weap
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Weak Service Permissions

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Weak Service Permissions This quick lab covers two Windows service misconfigurations that allow an attacker to elevate their privileges: 1. A low privileged user is allowed to change service configuration - for example change the service binary the service launches when it star
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: 🛠️ Weak service permissions

- **Provenance:** Source: `CYBER_CPT/hacker_recipes` | CWE: `CWE-269`
- **Context / Surface:** Source: hacker_recipes (en)
- **Root Cause / Analysis:** # Weak service permissions ## Theory File permissions in Windows define who is allowed to access, modify, or execute files on the system. If these permissions are misconfigured, they can enable unauthorized users to alter or replace critical files, potentially leading to security
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: WebEx Local Service Permissions Code Execution

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-269`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # WebEx Local Service Permissions Code Execution / / / / / --- / --- / --- / / EKU-ID: 8076 / CVE: 2018-15442 / OSVDB-ID: / / Author: Jeff McJunkin / Published: 2018-10-25 / Verified: / 'ruby ## # This module requires Metasploit: https://metasploit.com/download # Current source
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Windows Escalate Task Scheduler XML Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-269`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** CTF notepad * Home * All posts * Tags * Categories * About Home » Posts # Deadface CTF October 22, 2023 6 min ![\\"\\"] (\\"https://meashiri.github.io/ctf- writeups/posts/202310-deadfacectf/deadface_banner.png\\") Table of Contents * Crypto * Coin Code * Letter Soup * Bitz And Bol
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
