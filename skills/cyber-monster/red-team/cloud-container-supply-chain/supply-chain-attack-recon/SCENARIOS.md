# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`supply-chain-attack-recon`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Compromise Software Supply Chain

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Compromise Software Supply Chain **ID**: T1195.002 **Type**: Technique **Tactics**: Initial Access **Platforms**: Linux, Windows, macOS Adversaries may manipulate application software prior to receipt by a final consumer for the purpose of data or system compromise.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: APT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-1357`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** APT was a clinic in finding little things to exploit in a Windows host. I’ll start with access to only RPC and HTTP, and the website has nothing interesting. I’ll use RPC to identify an IPv6 address, which when scanned, shows typical Windows DC ports. Over SMB, I’ll pull a zip co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: T1112 - Modify Registry

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-1357`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1112 - Modify Registry ## Description from ATT&CK Adversaries may interact with the Windows Registry as part of a variety of other techniques to aid in defense evasion, persistence, and execution. Think of the Windows Registry as the central nervous system or the master config
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HackTheBox Writeup — Registry

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-1357`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # HackTheBox Writeup — Registry Greetings everyone !!! Today I am here with the story of how I owned my first hard rated machine Registry from Hackthebox Let’s get started ## Reconnaissance As always starting with the basic Nmap scan. 'bash nmap -sC -sV -o/N namp/initial 10.10.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB —Registry Machine

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-1357`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # HTB — Registry Machine ## Walk through of HackTheBox Registry Machine 10.10.10.159 What you will learn from this box: 1. Docker basic operation 2. Experience with forward binding and reverse shells 3. Restic tool backup We'll start with enumeration, I like to use the Legion too
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: MagicGardens

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-1357`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** MagicGardens starts by exploiting a Django website, tricking it into approving a purchase for a premium subscription. With this subscription, I am able to include a cross-site scripting payload in a QRCode and collect the admin’s cookie. This provides access to the Django admin p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: CyberMonday

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-1357`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** CyberMonday is a crazy difficult box, most of it front-loaded before the user flag. I'll start with a website, and abuse an off-by-slash nginx misconfiguration to read a .env file and the Git source repo. I'll find a mass assignment vulnerability in the site allowing me to get ad
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
