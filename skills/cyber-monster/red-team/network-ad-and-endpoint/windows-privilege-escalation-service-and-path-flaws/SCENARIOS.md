# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-privilege-escalation-service-and-path-flaws`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Path Interception by Unquoted Path

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Path Interception by Unquoted Path **ID**: T1574.009 **Type**: Technique **Tactics**: Stealth, Execution **Platforms**: Windows Adversaries may execute their own malicious payloads by hijacking vulnerable file path references.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: Grandpa

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Grandpa was one of the really early HTB machines. It’s the kind of box that wouldn’t show up in HTB today, and frankly, isn’t as fun as modern targets. Still, it’s a great proxy for the kind of things that you’ll see in OSCP, and does teach some valuable lessons, especially if yo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Helpline Windows

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I luckily decided to use Helpline as my test run for Commando VM. That allowed me to avoid challenges that I would have faces using Kali. This is the primary intended route for Helpline, using Windows to connect to the host. Up to this point, my recon has provided credentials for
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Proxying Your Way to Code Execution – A Different Take on DLL Hijacking

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-269`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Proxying Your Way to Code Execution – A Different Take on DLL Hijacking DLL hijacking is a method attackers use to exploit vulnerabilities in endpoints to execute malicious code. > **Jargon: DLL (Dynamic Link Library)** — A shared code library on Windows that multiple programs
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: UNQUOTED SERVICE PATH vulnerability in Windows 10 Enterprise machine

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # UNQUOTED SERVICE PATH vulnerability in Windows 10 Enterprise machine 1. INTRODUCTION * Suppose we find a machine in a given network, I’ll be demonstrating how to approach it from reconnaissance to getting low level privileges and then performing privilege escalation to get the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Blackfield

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Blackfield was a beautiful Windows Activity directory box where I’ll get to exploit AS-REP-roasting, discover privileges with bloodhound from my remote host using BloodHound.py, and then reset another user’s password over RPC. With access to another share, I’ll find a bunch of pr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Intro to Desktop Application Testing Methodology

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-269`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** 1. **Analyze the Request:** * **Role:** Master cybersecurity educator. * **Target Audience:** Bright but novice security learner. * **Goal:** Deeply elucidate, make complex intuitive, implicit explicit. * **UNBREAKABLE RULES:** * (a) Technical Correctness: Preserve all details, d
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
