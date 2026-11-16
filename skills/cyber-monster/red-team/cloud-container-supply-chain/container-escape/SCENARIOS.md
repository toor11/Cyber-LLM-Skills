# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`container-escape`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Worker container escape lead to arbitrary file reading in host machine [again]

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: After a successful build, LGTM allow user to view the file list. By default, only source code files and build config files are reserved ('lgtm.yml' and '.lgtm.yml').
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Worker container escape lead to arbitrary file reading in host machine

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Because lack of security, attacker will be able to remove original log file and replace it will a symlink to other file, After finishing job, host machine copy file from docker container.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: HTB Goodgames Walkthrough: Exploiting SQL Injection, SSTI, and Docker escape

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HTB Goodgames Walkthrough: Exploiting SQL Injection, SSTI, and Docker escape Introduction This write-up documents my journey solving the “GoodGames” machine on Hack The Box, categorized as Easy-Medium.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: The Great Escape Tryhackme Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** The Great Escape Tryhackme Writeup Room link: https://tryhackme.com/room/thegreatescape Docker, Networks, and Container Escapes; Oh My! I wanted to explore the concept of a Docker Escape.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: Exploiting Privileged Container Permissions — Part 1

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Exploiting Privileged Container Permissions — Part 1 With the rapid adaptation of containerization technology, also comes the risk of new security misconfigurations. Before we dive into exploiting these vulnerabilities… lets take a step back and figure out what exactly a “container” is.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: HTB Goodgames Walkthrough: Exploiting SQL Injection, SSTI, and Docker escape

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # HTB Goodgames Walkthrough: Exploiting SQL Injection, SSTI, and Docker escape Introduction This write-up documents my journey solving the “GoodGames” machine on Hack The Box, categorized as Easy-Medium. The challenge involved exploiting SQL Injection to gain admin access, levera
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: "CoRJail: From Null Byte Overflow To Docker Escape Exploiting poll_list Objects In The Linux Kernel"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # [corCTF 2022] CoRJail: From Null Byte Overflow To Docker Escape Exploiting poll_list Objects In The Linux Kernel ![[corCTF 2022] CoRJail: From Null Byte Overflow To Docker Escape Exploiting poll_list Objects In The Linux Kernel] (assets/images/title.png) CoRJail is a kernel expl
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Privileged Accounts and Token Privileges

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Privileged Accounts and Token Privileges Administrators, Domain Admins, Enterprise Admins are well known AD groups that allow for privilege escalation, that pentesters and red teamers will aim for in their engagements, but there are other account memberships and access token pr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
