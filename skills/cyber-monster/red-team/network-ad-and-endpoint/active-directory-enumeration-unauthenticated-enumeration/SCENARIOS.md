# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-enumeration-unauthenticated-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Microsoft Windows NT 4.0/SP 1/SP 2/SP 3/SP 4/SP 5 - Null Session Admin Name

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-284`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # College CTF: Reversing Challenge みなさん、こんにちは! A week back, one of my seniors published a series of three CTF challenges from Cryptography, Reversing and Forensics. This write up focuses on the Reversing challenge. ## First look at the Binary I always like to perform some easy te
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Windows NT allows remote attackers to list all users in a domain by obtaining the domain SID with th

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-284`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Windows NT allows remote attackers to list all users in a domain by obtaining the domain SID with the LsaQueryInformationPolicy policy function via a null session and using the SID to list the users. - **CVE**: CVE-2000-1200 - **Exploit Type**: InTheWild - **Exploit ID**: InThe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Null Session Allowed

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-284`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Null Session Allowed Checks if null sessions are allowed via any entry in the NullSessionPipes registry key, posing a security risk. - **Template ID**: null-session-allowed - **Severity**: high - **Author**: princechaddha - **Category**: Code - **Tags**: windows, null-session,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
