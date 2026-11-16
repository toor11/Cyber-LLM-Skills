# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ntlm-relay-and-coercion-coercion-primitives`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-294`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate This is a quick lab to familiarize with an Active Directory Certificate Services (ADCS) + PetitPotam + NLTM Relay technique that allows attackers, given ADCS is misconfigured (which i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: DarkCorp

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkCorp lives up to its insane difficulty, with three hosts, including a Windows AD domain, and starts with a Debian web/mail server. I’ll exploit an XSS in RoundCube to get access to the admin’s emails, leaking a private subdomain. I’ll reset the admin’s password and get into t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: VulnCicada

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I'll find an open NFS share on VulnCicada, and exfil two images. One of them has a password on a sticknote, which I'll use to get authenticated to the domain. From there, I'll enumerate ADCS and find the DC vulnerable to ESC8. I'll show how to do this attack from Linux, creating
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Barbhack 2025 CTF

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![cascade] (/icons/barbhack-2025.png) Members of the NetExec team created a small lab as a CTF for the Barbhack conference that took place in August 2025 in the South of France. There are four Windows servers on an Active Directory domain. I’ll find a leaked password on a printer
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
