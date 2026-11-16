# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sql-injection-sqlite-variants`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB-Socket

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HTB-Socket Overview: Hi, today I’m going to write a walkthrough for the latest box: Socket. For the user part, we need to use sqlite injection to get user’s credential for ssh. And for root part, we need to use the spec file packaging method of pyinstaller to escalate privilege.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: HTB — Socket

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=5)
- **Root Cause / Analysis:** HTB — Socket A detailed walkthrough for solving Socket Box on HTB. The box contains vulnerability like SQLite Injection, Weak Hashing and privilege escalation through SUDO shell scaping. Enumeration NMAP Let's start with an NMAP Scanning to enumerate open ports and the services running on the IP.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: HTB: Drive

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-89`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Drive has a website that provides cloud storage. I'll abuse an IDOR vulnerability to get access to the administrator's files and leak some creds providing SSH access. From there I'll access a Gitea instance and use the creds to get access to a backup script and the password for s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Health

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-89`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Health originally released as easy, but was bumped up to Medium three days later. That’s because there’s a tricky SQL injection that you have to exploit via a redirect, which eliminates things like sqlmap. After using the SSRF into redirect to exploit Gogs and leak the user table
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: PC

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-89`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** PC starts with only SSH and TCP port 50051 open. I'll poke at 50051 until I can figure out that it's GRPC, and then use grpcurl to enumerate the service. I'll find an SQL injection in the SQLite database and get some creds that I can use over SSH. To escalate, I'll find an instan
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: SQLite Injection

- **Provenance:** Source: `CYBER_CPT/payloads_all_the_things` | CWE: `CWE-89`
- **Context / Surface:** Source: payloads_all_the_things (en)
- **Root Cause / Analysis:** # SQLite Injection > SQLite Injection is a type of security vulnerability that occurs when an attacker can insert or "inject" malicious SQL code into SQL queries executed by an SQLite database. This vulnerability arises when user inputs are integrated into SQL statements without
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: who knows john dows?

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-89`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** 0xdf hacks stuff Home About MeTagsCheatsheets![\\"\\"] (\\"/icons/youtube.png\\"/)YouTube ![\\"\\"] (\\"/icons/gitlab.png\\"/)Gitlab![\\"\\"] (\\"/icons/rss.png\\"/)feed![\\"Buy] (\\"https://cdn.buymeacoffee.com/buttons/bmc- new-btn-logo.svg\\") # 2024 SANS Holiday Hack Challenge: Sn
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Cells Blog 3.3 - Reflected Cross-Site Scripting / Blind SQLite Injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-89`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # HTB: TwoMillion Walkthrough Writeup — TwoMillion By Araiz Naqvi # Overview - Difficulty: Easy - Operating System: Linux - Objective: Understand potential breaking points in twomillion machine. - Tools Used: nmap, nc, curl, ffuf, burpsuite, de4js, cyberchef, SSH I tend to start
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
