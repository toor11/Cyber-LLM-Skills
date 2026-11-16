# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-fingerprinting-and-tech-detection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: BASIC PENTESTING MACHINE

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** BASIC PENTESTING MACHINE https://tryhackme.com/room/basicpentestingjt ENUMERATION Nmap enumeration, high verbosity, version detection, using default script and guess OS detect bash nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess 10.10.167.101 Enumerating SMB Services Options #1: Enumerating SMB...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: Tryhackme Blue CTF

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Tryhackme Blue CTF Task 1: Recon a. Scan the machine. (If you are unsure how to tackle this, I recommend checking out the Nmap room) bash $ nmap -sV -vv -script vuln IP -sV = enable version detection.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: Hackthebox — Mango Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Hackthebox — Mango Writeup We first run nmap scan. > -sC : a script scan using the default set of scripts > > -sV : version detection We get ssh on port 22, http on port 80, https on port 443. We add staging-order.mango.htb, which is a host name, into our hosts file.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: Pandora — HTB(Hack The Box) Write-up

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Network Enumeration I started with an nmap scan for services and version detection, found OpenSSH and when you see that, you have to hammer on it. bash $ sudo nmap -sC -sV 10.10.11.136 -Pn -oN nmap_all.txt Starting Nmap 7.92 ( https://nmap.org ) at 2022–04–07 00:03 WAT Nmap scan report for 10.10.11.136 Host is up...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: Stocker — HackTheBox Machine Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Stocker — HackTheBox Machine Walkthrough First, we use the Nmap scan for checking open ports of the machine. We can do a very simple default scan, version detection scan and quick scan. We can see from the Nmap scan that ports 22 and 80 are open which related to the ssh and HTTP protocols.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: Jerry Machine

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Jerry Machine Let's start with an Nmap scan to see what kind of services are running on the Jerry machine. bash Nmap -A 10.10.10.95 -A: Enable OS detection, version detection, script scanning, and traceroute. After getting our Nmap scan results, we can see that port 8080 is open and it's running Tomcat version 7.0.88.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: Netmon Machine

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Netmon Machine Let’s go ahead and start by running an Nmap scan of the Netmon machine. Nmap -A -A: Enable OS detection, version detection, script scanning, and traceroute This time, the Nmap scan returned a lot of information, which was quite surprising.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Traverxec Machine

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Traverxec Machine Let’s start with an Nmap scan on the Traverxec machine to gather information about open ports and services running on the machine. bash nmap -A 10.129.240.199 * A: Enable OS detection, version detection, script scanning, and traceroute The Nmap results indicate that ports 22 and 80 are open on...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
