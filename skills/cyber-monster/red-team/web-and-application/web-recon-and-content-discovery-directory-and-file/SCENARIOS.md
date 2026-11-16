# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-recon-and-content-discovery-directory-and-file`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: TryHackMe Smag Grotto Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe Smag Grotto Walkthrough nmap scan: nmap -A -Pn Accessing page on port 80, we get gobuster: gobuster dir -u http:///w/usr/share/wordlists/dirb/common.txt -x php we got /mail.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: Mustacchio

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Mustacchio Enumeration Nmap text nmap -p- -v 10.10.68.59 PORT STATE SERVICE 22/tcp open ssh 80/tcp open http 8765/tcp open ultraseek-http Gobuster text gobuster dir -u http://10.10.68.59 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -x txt,html,gz,php,js,zip,img,bak -t 45...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: Lian_Yu — TryHackMe Writeup by Karthikeyan

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Lian_Yu — TryHackMe Writeup A beginner level security challenge Task 1 — Find the Flags 1. Deploy the VM and Start the Enumeration 2. What is the Web Directory you found? bash Hint: gobuster dir -e -u http://10.10.26.241/ -w /usr/share/dirbuster/wordlists/directory-list-lowercase-2.3-medium.txt Ans: 2100 3.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: Vulnerversity

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Vulnversity RECONNAISSANCE bash nmap -A -sT 10.10.234.51 -p- nmap -O -sT 10.10.234.51 to gather OS info Task 2: Locating directories with gobuster bash gobuster dir -u http://10.10.234.51:3333 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt so i found that the /internal directory is the one with the...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: BASHED — OSCP LIKE HTB Machine

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** BASHED — OSCP LIKE HTB Machine Let's start with our first step: Open Ports enumerations using basic nmap scan. From the nmap scan we can see there is one port open i.e., 80 Let's do a directory brute force using dirb: from dirb result we come across /dev, /uploads directory, let's see what's there using a web browser.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: Mirai (htb) writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Mirai (htb) writeup Enumeration Link to box Another box from TJNulls list. This time we have several open ports. Checking port 80 we see a blank site. Running gobuster: bash └─$ sudo gobuster dir -u http://10.129.18.92/ -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt --status-codes-blacklist...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: Oopsie HTB / WriteUp

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Oopsie HTB / WriteUp $ nmap -sV -sC -p- $IP -oN nmap-$IP.out whatweb $IP > whatweb.out We can remember that possible user is admin. $ gobuster dir -w /usr/wl/dirbuster-m.txt -x txt,php -u http://$1 -o gbdir-$1-http.out $ curl -X OPTIONS -I http://$IP/uploads/ $ nikto -h $IP Website (:80) At the bottom of the page we...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: HTB: Gofer

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-20`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Gofer starts with a proxy that requires auth. I’ll bypass this using different HTTP verbs, and get access to the proxy that allows for gopher protocol. I’ll use that to interact with an internal SMTP server and send a phishing email to one of the users with a LibreOffice Writer (
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
