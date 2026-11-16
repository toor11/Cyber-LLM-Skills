# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`linux-privilege-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Linux privilege escalation via trusted $PATH in keybase-redirector

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** keybase-redirector is a setuid root binary. keybase-redirector calls the fusermount binary using a relative path and the application trusts the value of $PATH. This allows a local, unprivileged user to trick the application to executing a custom fusermount binary as root.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Ubuntu Linux privilege escalation (dirty_sock)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi team, This week, I have publicly disclosed the dirty_sock local root exploit affecting multiple Linux Operating Systems. Very detailed information on the vulnerability can be found in my blog posting here. And the exploit code can be found in my GitHub repository here.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: TryHackMe — Advent of Cyber 2 — Day 11

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe — Advent of Cyber 2 — Day 11 Good afternoon all, Today’s challenge will have a focus on privelege escalation. Reading through the learning portion we will be using the SUID bits and utilizing the GTFOBins site. Anyhow, today’s intro: > "This is it — the moment that Elf McEager has been waiting for.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: THM — Linux Priv Esc

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** THM — Linux Priv Esc This room is aimed at walking you through a variety of Linux Privilege Escalation techniques. Below are some of the tasks: Task 2 : Service Exploits The MySQL service is running as root and the “root” user for the service does not have a password assigned.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: How to use GTFOBins — Tryhackme-Jr Penetration tester

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** How to use GTFOBins Tryhackme — Jr Penetration tester — Room — Linux PrivEsc- Task 6 -Privilege Escalation: Sudo > Task 6 Privilege Escalation: Sudo Solution 1: — using https://gtfobins.github.io/ https://gtfobins.github.io/ is a valuable source that provides information on how any program, on which you may have...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: TryHackMe — Jr Penetration Tester / Privilege Escalation / Linux Privesc / Part 2

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe — Jr Penetration Tester / Privilege Escalation / Linux Privesc / Part 2 This would be the much awaited, the fourteenth and the last write-up for our series of TryHackMe learning Path- Jr Penetration Tester.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: TRY HACK ME: Write-Up Privilege Escalation: Linux PrivEsc –Kernel Exploits, Sudo, SUID

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TRY HACK ME: Write-Up Privilege Escalation: Linux PrivEsc – Kernel Exploits, Sudo, SUID Task 5 Privilege Escalation: Kernel Exploits Note: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: TRY HACK ME: Write-Up Privilege Escalation: Linux PrivEsc –Capabilities, CronJobs, PATH

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TRY HACK ME: Write-Up Privilege Escalation: Linux PrivEsc – Capabilities, CronJobs, PATH Task 8 Privilege Escalation: Capabilities: Note: Launch the target machine attached to this task to follow along. You can launch the target machine and access it directly from your browser.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
