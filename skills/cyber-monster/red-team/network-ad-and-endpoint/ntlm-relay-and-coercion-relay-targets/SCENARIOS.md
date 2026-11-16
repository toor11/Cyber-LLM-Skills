# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ntlm-relay-and-coercion-relay-targets`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: LDAP Signing & Channel Binding Hardening

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** LDAP Signing & Channel Binding Hardening {{#include ../../banners/hacktricks-training.md}} Why it matters LDAP relay/MITM lets attackers forward binds to Domain Controllers to obtain authenticated contexts.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: APT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** APT was a clinic in finding little things to exploit in a Windows host. I’ll start with access to only RPC and HTTP, and the website has nothing interesting. I’ll use RPC to identify an IPv6 address, which when scanned, shows typical Windows DC ports. Over SMB, I’ll pull a zip co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: DarkCorp

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkCorp lives up to its insane difficulty, with three hosts, including a Windows AD domain, and starts with a Debian web/mail server. I’ll exploit an XSS in RoundCube to get access to the admin’s emails, leaking a private subdomain. I’ll reset the admin’s password and get into t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: University

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** University is a monster insane level machine. I'll start with a website and exploit a CVE in the process of generating a PDF copy of my profile to get a shell on the host. I'll find the same user's creds in a PowerShell script, and use them to log into not only this host, but two
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB Sherlock: Reaper

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Reaper is the investigation of an NTLM relay attack. The attacker works from within the network to poison an LLMNR response when a victim has a typo in the host in a share path. This results in the victim authenticating to the attacker, who relays the authentication to another wo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Barbhack 2025 CTF

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![cascade] (/icons/barbhack-2025.png) Members of the NetExec team created a small lab as a CTF for the Barbhack conference that took place in August 2025 in the South of France. There are four Windows servers on an Active Directory domain. I’ll find a leaked password on a printer
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
