# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`threat-hunting`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Urgent: attacker can access every data source on Bime

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnerability details I don't include words like "urgent" in my title very often, but I thought you might want to get onto this right away. An attacker can access the data source of any other customer on the BIME platform through the '/cube_models.json' endpoint.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Hunting for C2 Traffic

- **Provenance:** Source: `CYBER_CPT/netresec`
- **Context / Surface:** PCAP / Network Forensics (en)
- **Root Cause / Analysis:** Hunting for C2 Traffic In this video I look for C2 traffic by doing something I call Rinse-Repeat Threat Hunting, which is a method for removing "normal" traffic in order to look closer at what isn't normal.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Conti Ransomware— Threat Hunting with Splunk

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Conti Ransomware— Threat Hunting with Splunk Conti Ransomware Note This article provides my approach for solving the TryHackMe room titled “Conti”, created by heavenraiza. An Exchange server was compromised with ransomware and we must use Splunk to investigate how the attackers compromised the server.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: Advent of Cyber 2022 [Day 14]-Packet Analysis / Simply having a wonderful pcap time — Simple Write…

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Advent of Cyber 2022 [Day 13] Packet Analysis / Simply having a wonderful pcap time Why Does Packet Analysis Still Matter? * Network traffic is a pure and rich data source. A Packet Capture (PCAP) of network events provides a rich data source for analysis.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: TryHackMe Brim — Task 1 Introduction, Task 2 What is Brim?, & Task 3 The Basics

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe Brim — Task 1 Introduction, Task 2 What is Brim?, & Task 3 The Basics Learn and practice log investigation, pcap analysis and threat hunting with Brim. Task 1 Introduction BRIM is an open-source desktop application that processes pcap files and logs files. Its primary focus is providing search and analytics.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: Try Hack Me — Threat Hunting: Endgame — Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Try Hack Me — Threat Hunting: Endgame — Walkthrough Link to room:: https://tryhackme.com/room/threathuntingendgame Level:: Medium Tags:: #ThreatHunting, #Kibana, #ActionAndObjectives, #Exfiltration, #Impact This is the third newly released SOC L2 section room. Enjoy and use it only if you get stuck please.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: Threat Hunting With YARA — Motion Graphics Writeup TryHackMe // Detailed Walkthrough // SuNnY

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Threat Hunting With YARA — Motion Graphics Writeup TryHackMe Task 1 : Introduction In this module basics like Learning Objectives and Prerequisites are shared, it’s adviced to go through this module at least once.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Yara Write-up

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Yara Write-up Description Learn the applications and language that is Yara for everything threat intelligence, forensics, and threat hunting! This is a room on TryHackMe.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
