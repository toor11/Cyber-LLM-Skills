# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-certificate-services`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HackTheBox : Manager

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=5)
- **Root Cause / Analysis:** HackTheBox : Manager Manager is a Windows machine which hosts an Active Directory environment with AD CS (Active Directory Certificate Services), a web server, and an SQL server. The foothold involves enumerating users using RID cycling and performing a password spray attack to gain access to the MSSQL service.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: VulnCicada

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I'll find an open NFS share on VulnCicada, and exfil two images. One of them has a password on a sticknote, which I'll use to get authenticated to the domain. From there, I'll enumerate ADCS and find the DC vulnerable to ESC8. I'll show how to do this attack from Linux, creating
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Shibuya

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Shibuya starts with a brute force user enumeration over Kerberos, finding two machine accounts with their passwords set to their username. I'll use those to enumerate LDAP, finding credentials for a service account in a comment. That user has access to an SMB share with three Win
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Authority

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Authority is a Windows domain controller. I’ll access open shares over SMB to find some Ansible playbooks. I’ll crack some encrypted fields to get credentials for a PWM instance. The PWM instance is in configuration mode, and I’ll use that to have it try to authenticate to my box
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Certificate

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Certificate starts with a school website that accepts assignment uploads in limited formats that includes zip archives. I'll show two ways to bypass the filters in PHP and upload a webshell - first with a null byte in the filename inside the zip, and then by stacking two zips tog
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: EscapeTwo

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** EscapeTwo starts with an assume breach scenario, a simple windows account with creds. I'll use those to find a broken Excel workbook, which I'll recover passwords from to get sa access to MSSQL. From there I'll enable xp-cmdshell and get a foothold on the box. There I'll find mor
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
