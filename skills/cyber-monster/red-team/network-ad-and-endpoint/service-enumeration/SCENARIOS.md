# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`service-enumeration`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Active Walkthrough HTB

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Active Walkthrough HTB This is easy machine regarding active directory. I definitely recommend ones who are unfamiliar with active directory for starting. Let's start with service enumeration via nmap. bash nmap 10.10.10.100 -p- -T 4 -oN nmap-initial-scan As we can see this is actice directory because of 88 port.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: SAU walk-through HTB

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** SAU walk-through HTB Sau is easy linux machine that fit definitely for beginner.Let's start with service enumeration. bash nmap 10.10.11.224 -p- -T 4 -oN nmap-initial-scan nmap 10.10.11.224 -p22,80,8338,55555 -sV -sC -oN nmap-full-scan As we can see tcp 22,80,8338 and 55555 ports are open but 80 and 8338 ports are...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: 03. Kenobi

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Kenobi Scanning First we will deploy the machine and scan the target using rustscan. Enumeration We can see that there is Samba file server running, so let’s find the available shares. bash smbclient -L 10.10.74.95 We will now connect to the anonymous share.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: TryHackMe BasicPentesting

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** BasicPentesting Walkthrough Room https://tryhackme.com/r/room/basicpentestingjt Author Notes * Victim machine ip address is 10.10.68.136 What will you learn? * brute forcing * hash cracking * service enumeration * Linux Enumeration Questions * Let’s do nmap scan bash nmap -sC -T4 10.10.68.136 nmap output text PORT...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: HackTheBox - Machines/ SwagShop

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox - SwagShop SwagShop is one of the easy boxes on HTB. It reminded me OSCP labs and was a good practice for me to prepare for exam. NMAP Scan Lets start with a usual nmap scan with service enumeration (-sV) and execution of default NSE scripts (-sC). As a result, only SSH and HTTP ports are open.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: HackTheBox- Armageddon Walkthrough / TheHiker

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox - Armageddon Walkthrough Initial Scan Service Enumeration We can see from the second scan that the http-generator in use is "Drupal 7". "Drupal is a free and open-source web content management system written in PHP and distributed under the GNU General Public License.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: HTB: Pit

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Pit used SNMP in two different ways. First, I’ll enumerate it to leak the location of a webserver running SeedDMS, where I’ll abuse a webshell upload vulnerability to get RCE on the host. I’m not able to get a reverse shell because of SeLinux, but I can enumerate enough to find a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: AirTouch

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** AirTouch simulates a wireless network environment. I’ll start by pulling a default password from SNMP to SSH as a consultant user inside a container with virtual wireless interfaces. From there, I’ll capture and crack a WPA2-PSK handshake to join the tablet network, then decrypt
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
