# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sql-injection-waf-tamper-chains`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: NahamCon 2022 CTF Write-up: “No Space Between Us” Challenge

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-89`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # No Space Between Us — Walkthrough As you can see in the challenge description, there appears to be a creative storyteller bot in the CTF’s Discord server, but the interesting part of the description was the second part of the sentence which states: “There needs to be zero space
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Second Order SQL-Injection on HTB Nightmare

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-89`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Nightmare just retired, and it was an insanely difficult box. Rather than do a full walkthrough, I wanted to focus on a write-up of the second-order SQL injection necessary as a first step for this host. ## Second Order SQL Injection In a typical SQL Injection, user input is used
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Linux - Missing Locking Between ELF coredump code and userfaultfd VMA Modification

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-89`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Linux - Missing Locking Between ELF coredump code and userfaultfd VMA Modification EKU-ID: 50849 CVE: CVE-2019-11599 Author: Google Security Research Published: 2019-04-30 elf_core_dump() has a comment back from something like 2.5.43-C3 that says: /* * We no longer stop all VM
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Multimaster

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-89`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Multimaster] (https://0xdfimages.gitlab.io/img/multimaster-cover.png) Multimaster was a lot of steps, some of which were quite difficult. I’ll start by identifying a SQL injection in a website. I’ll have to figure out the WAF and find a way past that, dumping credentials but als
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Read between the lines

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-89`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** HTTP (Hyper Text Transfer Protocol) is basically a client-server protocol, wherein the client (web browser) makes a request to the server and in return, the server responds to the request. The response by the server is mostly in the form of HTML formatted pages. HTTP protocol by
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: KubeVirt Excessive Role Permissions Could Enable Unauthorized VMI Migrations Between Nodes

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-89`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary The permissions granted to the 'virt-handler' service account, such as the ability to update VMI and patch nodes, could be abused to force a VMI migration to an attacker-controlled node. ### Details Following the [GitHub security advisory published on March 23 2023] (h
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
