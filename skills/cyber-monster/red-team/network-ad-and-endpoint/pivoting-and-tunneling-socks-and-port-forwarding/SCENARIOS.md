# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`pivoting-and-tunneling-socks-and-port-forwarding`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: TryHackMe — Badbyte Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe — BadByte Walkthrough Badbyte (https://tryhackme.com/room/badbyte) covers many important aspects of penetration testing such as importance of enumeration, hash cracking, port forwarding, web exploitation and privilege escalation.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: HTB Buff [writeup]

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HTB Buff [writeup] Unauthenticated RCE / Buffer Exploit / Port Forwarding Summary This machines teaches you how to exploit a simple application that is vulnerable to unauthenticated RCE to get user shell. For root exploitation, it require modifying the buffer exploit code and port forwarding techniques.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: Hack the Box — Explore Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Hack the Box — Explore Walkthrough Details * OS: Android * Difficulty: 3.6/10 * Release: 17/08/2021 * IP: 10.10.10.147 * Box Author: bertolis Knowledge/Skill Requirements * SSH Port Forwarding * Android OS + associated tools (ADB, ES File Explorer) * I used my Kali Linux VM to complete this.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Anubis

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Anubis starts simply enough, with a ASP injection leading to code execution in a Windows Docker container. In the container I’ll find a certificate request, which leaks the hostname of an internal web server. That server is handling software installs, and by giving it my IP, I’ll
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Feline

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Feline was another Tomcat box, this time exploiting a neat CVE that allowed me to upload a malcious serialized payload and then trigger it by giving a cookie that points the session to that file. The rest of the box focuses on Salt Stack, an IT automation platform. My foothold sh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: DarkCorp

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkCorp lives up to its insane difficulty, with three hosts, including a Windows AD domain, and starts with a Debian web/mail server. I’ll exploit an XSS in RoundCube to get access to the admin’s emails, leaking a private subdomain. I’ll reset the admin’s password and get into t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: Build

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Build starts with a Jenkins backup on an rsync server. I’ll download and decrypt a password to get access to a Gitea instance. I’ll update a Jenkins pipeline and get execution in a Docker container I’ll find PowerDNS-Admin running in another container, and on gaining access to th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
