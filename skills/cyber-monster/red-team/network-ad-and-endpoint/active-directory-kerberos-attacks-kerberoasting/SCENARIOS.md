# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-kerberos-attacks-kerberoasting`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Blackfield-HTB

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Blackfield-HTB Blackfield is the Hack The Box Hard-Level box. We get login into smb shares and enumerated profiles$ shares. where we got lots of usernames. We used a kerberoasting attack on an active directory to obtain credentials.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: HTB: Active

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Active was an example of an easy box that still provided a lot of opportunity to learn. The box was centered around common vulnerabilities associated with Active Directory. There's a good chance to practice SMB enumeration. It also gives the opportunity to use Kerberoasting again
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Scrambled [From Linux]

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ## Recon ### nmap 'nmap' finds many TCP ports: 'bash oxdf@hacky$ nmap -p- --min-rate 10000 10.10.11.168 Starting Nmap 7.80 ( https://nmap.org ) at 2022-06-09 12:45 UTC Nmap scan report for 10.10.11.168 Host is up (0.097s latency). Not shown: 65515 filtered ports PORT STATE SERV
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB Endgame: XEN

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Endgame XEN is all about owning a small network behind a Citrix virtual desktop environment. I’ll phish creds for the Citrix instance from users in the sales department, and then use them to get a foothold. I’ll break out of the restrictions in that environment, and then get admi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB Sherlock: Campfire-1

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Campfire-1 is the first in a series of Sherlocks looking at identifying critical active directory vulnerabilities. This challenge requires looking at event log and prefetch data to see an attack run PowerView and the Rubeus to perform a Kerberoasting attack. ## Background ### Sce
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Breach

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Breach is a Windows domain controller box. I'll start by using guest access to a writable SMB share to drop ntlm_theft lure files, capturing a NetNTLMv2 hash for a domain user with Responder. After cracking that hash, I'll use BloodHound to find a Kerberoastable MSSQL service acc
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
