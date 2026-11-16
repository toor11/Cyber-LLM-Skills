# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`service-enumeration-ldap-and-directory`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: BloodHound & Other Active Directory Enumeration Tools

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** BloodHound & Other Active Directory Enumeration Tools {{#include ../../banners/hacktricks-training.md}} {{#ref}} adws-enumeration.md {{#endref}} > NOTE: This page groups some of the most useful utilities to **enumerate** and **visualise** Active Directory relationships.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Hack The Box — Sauna

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Hack The Box — Sauna Overview Sauna is an easy difficulty Windows machine that features Active Directory enumeration and exploitation. The initial enumeration expose some Names using which we can create some username list.Using GetNPUsers.py we expose valid user and hash.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: [HTB] Timelapse Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** [HTB] Timelapse Write-up Hello! In this walkthrough we will be exploring the Timelapse machine. I’m actually studing for CPTS path in HTB, and after finishing the “Active Directory enumeration and attack” this box was recommended.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: Sauna: HTB Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Sauna: HTB Walkthrough About Sauna Sauna is an easy difficulty Windows machine that features Active Directory enumeration and exploitation. Possible usernames can be derived from employee full names listed on the website.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: HTB: Scrambled [From Linux]

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ## Recon ### nmap 'nmap' finds many TCP ports: 'bash oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.168 Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-09 12:45 UTC Nmap scan report for 10.10.11.168 Host is up (0.097s latency). Not shown: 65515 filtered ports PORT STATE SERV
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Vintage

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Vintage is another pure AD box, this time at Hard Level. I'll start with creds, and use them to collect Bloodhound data, which shows a computer object that's a member of the Pre-Windows 2000 Compatible Access group. This means I can guess it's password, and use that machine to ge
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Monitored

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Monitored is all about a Nagios XI monitoring system. I'll abuse it over and over to slowly escalate privileges ending up at root. I'll find initial creds from SNMP, but the account is disabled. I'll abuse the API to get a token that provides authentication to the site. From ther
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: Pikaboo

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Pikaboo required a lot of enumeration and putting together different pieces to get through each step. I’ll only ever get a shell as www-data and root, but for each step there’s several pieces to pull together and combine to some effect. I’ll start by abusing an off-by-slash vulne
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
