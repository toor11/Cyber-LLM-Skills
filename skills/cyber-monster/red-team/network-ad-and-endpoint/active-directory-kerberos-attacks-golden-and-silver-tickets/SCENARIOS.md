# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-kerberos-attacks-golden-and-silver-tickets`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Golden Ticket

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Golden Ticket **ID**: T1558.001 **Type**: Technique **Tactics**: Credential Access **Platforms**: Windows Adversaries who have the KRBTGT account password hash may forge Kerberos ticket-granting tickets (TGT), also known as a golden ticket.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Silver Ticket

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Silver Ticket **ID**: T1558.002 **Type**: Technique **Tactics**: Credential Access **Platforms**: Windows Adversaries who have the password hash of a target service account (e.g. SharePoint, MSSQL) may forge Kerberos ticket granting service (TGS) tickets, also known as silver tickets.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Diamond Ticket

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Diamond Ticket **Like a golden ticket**, a diamond ticket is a TGT which can be used to **access any service as any user**. A golden ticket is forged completely offline, encrypted with the krbtgt hash of that domain, and then passed into a logon session for use.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Golden Ticket

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Golden Ticket {{#include ../../banners/hacktricks-training.md}} Golden ticket A **Golden Ticket** attack consist on the **creation of a legitimate Ticket Granting Ticket (TGT) impersonating any user** through the use of the **NTLM hash of the Active Directory (AD) krbtgt account**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Silver Ticket

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Silver Ticket Silver ticket The **Silver Ticket** attack involves the exploitation of service tickets in Active Directory (AD) environments. This method relies on **acquiring the NTLM hash of a service account**, such as a computer account, to forge a Ticket Granting Service (TGS) ticket.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: TryHackMe Attacking Kerberos — Task 7 Golden/Silver Ticket Attacks w/ mimikatz

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe Attacking Kerberos — Task 7 Golden/Silver Ticket Attacks w/ mimikatz If you haven’t done task 6 yet, here is the link to my write-up it: Task 6 Pass the Ticket w/ mimikatz.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate This is a quick lab to familiarize with an Active Directory Certificate Services (ADCS) + PetitPotam + NLTM Relay technique that allows attackers, given ADCS is misconfigured (which i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: Scrambled [From Linux]

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ## Recon ### nmap 'nmap' finds many TCP ports: 'bash oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.168 Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-09 12:45 UTC Nmap scan report for 10.10.11.168 Host is up (0.097s latency). Not shown: 65515 filtered ports PORT STATE SERV
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
