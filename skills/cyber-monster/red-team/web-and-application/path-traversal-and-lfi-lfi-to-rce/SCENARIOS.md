# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`path-traversal-and-lfi-lfi-to-rce`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: LFI to RCE via PHPInfo

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** LFI to RCE via PHPInfo To exploit this technique you need all of the following: - A reachable page that prints phpinfo() output. - A Local File Inclusion (LFI) primitive you control (e.g., include/require on user input). - PHP file uploads enabled (file_uploads = On).
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: LFI to RCE via Temporary File Uploads

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** LFI to RCE via Temporary File Uploads {{#include ../../banners/hacktricks-training.md}} **Check the full details of this technique in https://gynvael.coldwind.pl/download.php?f=PHP_LFI_rfc1867_temporary_files.pdf** **PHP File uploads** When a **PHP** engine receives a **POST request** containing...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: TryHackMe: Archangel Writeup Español

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe: Archangel Writeup Este es mi primer writeup y trataré de que sea sencillo de entender. La máquina es boot2root llamada “Archangel” en TryHackMe donde: * Explotaremos un LFI. * Realizaremos un “Log Poisoning” que nos permitirá ejecución remota de comandos. * Por último, escalación de privilegios.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: dogcat — TryHackMe (2024)

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** dogcat — TryHackMe (2024) Apache Log Poisoning through LFI Link to machine : link Enumeration bash nmap -Pn -sV 10.10.196.202 Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-04-16 10:42 CEST Nmap scan report for 10.10.196.202 Host is up (0.089s latency).
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: HackTheBox — Nineveh Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox — Nineveh Writeup Nineveh is a Medium level OSCP like linux box on HackTheBox. The only challenging part is getting the initial shell via LFI to RCE. I have covered both the intended and unintended way here. ENUMERATION We find port 80 and 443 are open.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: HackTheBox — Bart Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox — Bart Writeup Bart is a Medium Level but challenging Windows machine on HackTheBox. Here we use PHP log poisoning to gain initial access and privilege escalate via Autologon Credentials or by using Juicy Potato. Another tricky part of this box was password guessing and bruteforcing.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: Solving the Skills Assessment: File Inclusion and Log Poisoning

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-22`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Solving the Skills Assessment: File Inclusion and Log Poisoning # Introduction CTF challenges are designed to test your skills in various aspects of cyber security, and this particular challenge focuses on exploiting File Inclusion vulnerabilities along with Log Poisoning. We’l
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: LFI to RCE via Log Poisoning

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-22`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # LFI to RCE via Log Poisoning Hello, I am W1C3, and today I will explain how to achieve LFI to RCE via Log Poisoning. This challenge was developed for the CyberArena CTF organized by Deloitte. ## Description You have been hired to conduct a penetration test on this web applicati
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
