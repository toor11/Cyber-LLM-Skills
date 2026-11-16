# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`linux-forensics`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: NordVPN Linux Client - Unsafe service file permissions leads to Local Privilege Escalation

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The Linux package available in NordVPN's repository is affected by a permission issue in init script and systemd unit files that allows any user on the system to execute arbitrary command as root.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: TryHackMe / Linux Forensics

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe / Linux Forensics A write up of Linux Forensics room of TryHackMe. https://tryhackme.com/room/linuxforensics > Task 1: Introduction (1). Go through the Learning Objectives _Answer_ : Learning Objectives: After completing this room, we will have learned: * An introduction to Linux and its different flavours.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: DISGRUNTLED (Try Hack Me Room) Write up

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** DISGRUNTLED (Try Hack Me Room) Write up DESCRIPTION This is a write-up for Try Hack Me Room — Disgruntled made to teach about Linux Forensics using the terminal. A cheatsheet will be provided in this room which will be helpful to find the right commands to find the answers to the provided questions.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: HTB: Curling

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Curling was a solid box easy box that provides a chance to practice some basic enumeration to find a password, using that password to get access to a Joomla instance, and using the access to get a shell. With a shell, I'll find a compressed and encoded backup file, that after a b
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Shrek

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Shrek is another 2018 HackTheBox machine that is more a string of challenges as opposed to a box. I’ll find an uploads page in the website that doesn’t work, but then also find a bunch of malware (or malware-ish) files in the uploads directory. One of them contains a comment abou
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: RE

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** RE was a box I was really excited about, and I was crushed when the final privesc didn’t work on initial deployment. Still, it got patched, and two unintended paths came about as well, and everything turned out ok. I’ll approach this write-up how I expected people to solve it, an
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Helpline Windows

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I luckily decided to use Helpline as my test run for Commando VM. That allowed me to avoid challenges that I would have faces using Kali. This is the primary intended route for Helpline, using Windows to connect to the host. Up to this point, my recon has provided credentials for
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
