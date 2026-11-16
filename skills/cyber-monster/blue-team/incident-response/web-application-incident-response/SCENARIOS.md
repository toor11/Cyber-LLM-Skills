# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-application-incident-response`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Web Shell

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Web Shell **ID**: T1505.003 **Type**: Technique **Tactics**: Persistence **Platforms**: Linux, macOS, Network Devices, Windows Adversaries may backdoor web servers with web shells to establish persistent access to systems.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: SEASHARPEE

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** SEASHARPEE **ID**: S0185 **Type**: Malware **Platforms**: Windows SEASHARPEE is a Web shell that has been used by OilRig. (Citation: FireEye APT34 Webinar Dec 2017)
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: VersaMem

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** VersaMem **ID**: S1154 **Type**: Malware **Platforms**: Network Devices VersaMem is a web shell designed for deployment to Versa Director servers following exploitation. Discovered in August 2024, VersaMem was used during Versa Director Zero Day Exploitation by Volt Typhoon to target ISPs and MSPs.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: BUSHWALK

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** BUSHWALK **ID**: S1118 **Type**: Malware **Platforms**: Network Devices BUSHWALK is a web shell written in Perl that was inserted into the legitimate querymanifest.cgi file on compromised Ivanti Connect Secure VPNs during Cutting Edge.(Citation: Mandiant Cutting Edge Part 2 January 2024)(Citation:...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Advent of Cyber 2024 [ Day 22 ] Writeup with Answers / TryHackMe Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Advent of Cyber 2024 [ Day 22 ] Writeup with Answers / TryHackMe Walkthrough It’s because I’m kubed, isn’t it? Task 28 — Kubernetes DFIR Day 22: It’s because I’m kubed, isn’t it? 1\. What is the name of the web shell that was used by Mayor Malware? 1.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: HackTheBox — Sniper (Walkthrough)

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox — Sniper (Walkthrough) Sniper was a fun box made by MinatoTW & felamos. The box included: * LFI * RFI * Web Shell * Port Forwarding * CHM exploitation Initial recon: To begin, the box was port scanned using nmap: text nmap 10.10.10.151 Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-08 10:00 AEDT Nmap...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: HackTheBox — Bashed

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox — Bashed Bashed is an Medium level Linux machine on Hack The Box. Here we have a php web shell already running on the developer's webserver which we use to get initial access and then privilege escalate using sudo and the finally privilege escalate using a python reverse shell due to a hidden cron job...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Bashed — HTB Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Bashed — HTB Writeup Summary Bashed is a retired box available on the Hack the Box platform. It is known as an easy Linux machine with a fairly easy to find foothold through a development web shell.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
