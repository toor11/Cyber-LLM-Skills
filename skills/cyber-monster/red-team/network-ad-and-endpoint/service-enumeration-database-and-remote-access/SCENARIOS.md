# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`service-enumeration-database-and-remote-access`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Eighteen

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Eighteen is a Windows Server 2025 assume-breach box starting with MSSQL credentials. I'll use MSSQL login impersonation to access the financial planner database and recover a Werkzeug PBKDF2 hash for the web admin. After cracking the hash and spraying the password against domain
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Scrambled [From Linux]

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ## Recon ### nmap 'nmap' finds many TCP ports: 'bash oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.168 Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-09 12:45 UTC Nmap scan report for 10.10.11.168 Host is up (0.097s latency). Not shown: 65515 filtered ports PORT STATE SERV
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Breach

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Breach is a Windows domain controller box. I'll start by using guest access to a writable SMB share to drop ntlm_theft lure files, capturing a NetNTLMv2 hash for a domain user with Responder. After cracking that hash, I'll use BloodHound to find a Kerberoastable MSSQL service acc
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Redelegate

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I’ll find files on an open FTP server to start Redelegate. These files include the results of a security audit and a shared KeePass database. I’ll crack the password and get access to MSSQL, where I can enumerate domain users. Then I’ll password spray to get a foothold on the dom
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Querier

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Querier was a fun medium box that involved some simple document forensices, mssql access, responder, and some very basic Windows Privesc steps. I'll show how to grab the Excel macro-enabled workbook from an open SMB share, and find database credentials in the macros. I'll use tho
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
