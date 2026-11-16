# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`service-enumeration-smb-and-netbios`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: 03. Kenobi

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Kenobi Scanning First we will deploy the machine and scan the target using rustscan. Enumeration We can see that there is Samba file server running, so let’s find the available shares. bash smbclient -L 10.10.74.95 We will now connect to the anonymous share.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: OpenAdmin / HTB / OSCP

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** OpenAdmin / HTB / OSCP Tanzil Rehman · Follow Published in Tanzil Rehman · 6 min read · Oct 15, 2021 \-- Listen Share Enumeration NMAP ┌──(root💀kali)-[/home/kali/htb/openadmin] └─# nmap -A -sV -sC -O -p- 10.10.10.171 Starting Nmap 7.91 ( https://nmap.org ) at 2021-10-15 02:23 EDT Nmap scan report for 10.10.10.171...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: PWK Notes: SMB Enumeration Checklist [Updated]

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ## Checklist * Enumerate Hostname - 'nmblookup -A [ip]' * List Shares + 'smbmap -H [ip/hostname]' + 'echo exit / smbclient -L \\\\[ip]' + 'nmap --script smb-enum-shares -p 139,445 [ip]' * Check Null Sessions + 'smbmap -H [ip/hostname]' + 'rpcclient -U "" -N [ip]' + 'smbclient \\\
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: DarkCorp

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkCorp lives up to its insane difficulty, with three hosts, including a Windows AD domain, and starts with a Debian web/mail server. I’ll exploit an XSS in RoundCube to get access to the admin’s emails, leaking a private subdomain. I’ll reset the admin’s password and get into t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Rebound

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Rebound is a monster Active Directory / Kerberos box. I’ll start off with a RID-cycle attack to get a list of users, and combine AS-REP-Roasting with Kerberoasting to get an crackable hash for a service account. That password is shared by a domain user, and I’ll find a bad ACL th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Fuse

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Fuse was all about pulling information out of a printer admin page. I’ll collect usernames and use cewl to make a wordlist, which happens to find the password for a couple accounts. I’ll need to change the password on the account to use it, and then I can get RPC access, where I’
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Active

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Active was an example of an easy box that still provided a lot of opportunity to learn. The box was centered around common vulnerabilities associated with Active Directory. There's a good chance to practice SMB enumeration. It also gives the opportunity to use Kerberoasting again
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: Forest

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** One of the neat things about HTB is that it exposes Windows concepts unlike any CTF I’d come across before it. Forest is a great example of that. It is a domain controller that allows me to enumerate users over RPC, attack Kerberos with AS-REP Roasting, and use Win-RM to get a sh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
