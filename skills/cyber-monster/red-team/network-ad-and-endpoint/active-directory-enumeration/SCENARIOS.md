# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

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

## Case 5: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Vintage

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Vintage is another pure AD box, this time at Hard Level. I'll start with creds, and use them to collect Bloodhound data, which shows a computer object that's a member of the Pre-Windows 2000 Compatible Access group. This means I can guess it's password, and use that machine to ge
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Rebound

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Rebound is a monster Active Directory / Kerberos box. I’ll start off with a RID-cycle attack to get a list of users, and combine AS-REP-Roasting with Kerberoasting to get an crackable hash for a service account. That password is shared by a domain user, and I’ll find a bad ACL th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: Intelligence

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Intelligence was a great box for Windows and Active Directory enumeration and exploitation. I’ll start with a lot of enumeration against a domain controller. Eventually I’ll brute force a naming pattern to pull down PDFs from the website, finding the default password for new user
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
