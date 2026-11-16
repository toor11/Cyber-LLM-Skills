# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-enumeration-authenticated-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Eighteen

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Eighteen is a Windows Server 2025 assume-breach box starting with MSSQL credentials. I'll use MSSQL login impersonation to access the financial planner database and recover a Werkzeug PBKDF2 hash for the web admin. After cracking the hash and spraying the password against domain
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Certificate

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Certificate starts with a school website that accepts assignment uploads in limited formats that includes zip archives. I'll show two ways to bypass the filters in PHP and upload a webshell - first with a null byte in the filename inside the zip, and then by stacking two zips tog
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Shibuya

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Shibuya starts with a brute force user enumeration over Kerberos, finding two machine accounts with their passwords set to their username. I'll use those to enumerate LDAP, finding credentials for a service account in a comment. That user has access to an SMB share with three Win
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Axlle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Axlle is a Windows host with some niche Windows exploitation paths. I’ll start by phishing a user using a Excel Add-On file, XLL. These are since mostly blocked, but were previously quite big in the phishing scene. Then I’ll modify a URL file to run my reverse shell. I’ll find co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Sauna

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Sauna was a neat chance to play with Windows Active Directory concepts packaged into an easy difficulty box. I’ll start by using a Kerberoast brute force on usernames to identify a handful of users, and then find that one of them has the flag set to allow me to grab their hash wi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Object

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Object was tricky for a CTF box, from the HackTheBox University CTF in 2021. I’ll start with access to a Jenkins server where I can create a pipeline (or job), but I don’t have permissions to manually tell it to build. I’ll show two ways to get it to build anyway, providing execu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
