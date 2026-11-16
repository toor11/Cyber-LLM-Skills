# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-privilege-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: CVE-2019-5443: Windows Privilege Escalation: Malicious OpenSSL Engine

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2019-5443`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: The curl windows binaries are built with OpenSSL libraries and have an insecure path for the OPENSSLDIR build parameter. This path is set to c:\usr\local\ssl. When curl is executed it attempts to load openssl.cnf from this path.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Microsoft Windows Privilege Escalation Vulnerability

- **Provenance:** Source: `CYBER_CPT/cisa_kev`
- **Context / Surface:** CISA KEV Advisory (en)
- **Root Cause / Analysis:** CVE-2019-0880: Microsoft Windows Privilege Escalation Vulnerability > **Jargon: CVE** — Common Vulnerabilities and Exposures, a standardized identifier for publicly known security flaws.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Microsoft Windows Privilege Escalation Vulnerability

- **Provenance:** Source: `CYBER_CPT/cisa_kev`
- **Context / Surface:** CISA KEV Advisory (en)
- **Root Cause / Analysis:** CVE-2002-0367: Microsoft Windows Privilege Escalation Vulnerability > **Jargon: CVE** — Common Vulnerabilities and Exposures, a standardized identifier for publicly known security flaws.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Path Interception by Unquoted Path

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Path Interception by Unquoted Path **ID**: T1574.009 **Type**: Technique **Tactics**: Stealth, Execution **Platforms**: Windows Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Checklist - Local Windows Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Checklist - Local Windows Privilege Escalation **Best tool to look for Windows local privilege escalation vectors:** **WinPEAS** [System Info] (windows-local-privilege-escalation/index.html#system-info) - [ ] Obtain [**System information**] (windows-local-privilege-escalation/index.html#system-info)...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: TryHackMe — Windows PrivEsc WalkThrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe — Windows PrivEsc WalkThrough This is a practical walkthrough of "Windows PrivEsc v 1.0" on TryHackMe. This room is created by Tib3rius aimed at understanding Windows Privilege Escalation techniques.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: Windows Privilege Escalation / TryHackMe

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Windows Privilege Escalation / TryHackMe Another day, another room. Today I am undertaking the Windows Privilege Escalation room. As with all my writeups, I am not providing perfect answers. This article will contain my mistakes too. Often, articles act like the answer was obvious, which is not always the case.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Windows Privilege Escalation: DNS Admin to NT Authority System — Step By Step

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Windows Privilege Escalation: DNS Admin to System Shell — Step-by-Step In this post, I will illustrate the process of escalation the privilege from DNS admin to NT Authority System shell. Let get started! I already got foothold on the victim machine using Evil-WinRM. I will proceed from here.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
