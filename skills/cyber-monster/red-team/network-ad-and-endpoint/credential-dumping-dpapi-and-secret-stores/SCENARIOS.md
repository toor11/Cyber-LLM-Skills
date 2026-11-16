# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`credential-dumping-dpapi-and-secret-stores`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Windows Credential Manager

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Windows Credential Manager **ID**: T1555.004 **Type**: Technique **Tactics**: Credential Access **Platforms**: Windows Adversaries may acquire credentials from the Windows Credential Manager.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: DPAPI - Extracting Passwords

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-522`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # DPAPI - Extracting Passwords ## What is DPAPI The Data Protection API (DPAPI) is primarily utilized within the Windows operating system for the **symmetric encryption of asymmetric private keys**, leveraging either user or system secrets as a significant source of entropy. This
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Voleur

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Voleur is an active directory box that starts with assume breach credentials. I’ll find an Excel notebook with credentials and get a shell. I’ll find a deleted user and switch to a service account to recover it. That user can access an SMB share with a user’s home directory backu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: DarkCorp

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkCorp lives up to its insane difficulty, with three hosts, including a Windows AD domain, and starts with a Debian web/mail server. I’ll exploit an XSS in RoundCube to get access to the admin’s emails, leaking a private subdomain. I’ll reset the admin’s password and get into t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Vintage

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Vintage is another pure AD box, this time at Hard Level. I'll start with creds, and use them to collect Bloodhound data, which shows a computer object that's a member of the Pre-Windows 2000 Compatible Access group. This means I can guess it's password, and use that machine to ge
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Office

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Office starts with a Joomla instance that leaks a password. I'll brute force usernames over Kerberos and then password spray to find where the password is reused. that use has access to an SMB share where I find a PCAP that includes a Kerberos authentication exchange. I'll build
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Reading DPAPI Encrypted Secrets with Mimikatz and C++

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-522`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Reading DPAPI Encrypted Secrets with Mimikatz and C++ This lab is based on the article posted by harmj0y: https://www.harmj0y.net/blog/redteaming/operational-guidance-for-offensive-user-dpapi-abuse/. The aim is to get a bit more familiar with DPAPI, explore some of the mimikatz
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
