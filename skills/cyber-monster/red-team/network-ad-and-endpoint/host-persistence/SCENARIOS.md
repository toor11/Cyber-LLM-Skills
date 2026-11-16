# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`host-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: NordVPN Linux Client - Unsafe service file permissions leads to Local Privilege Escalation

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The Linux package available in NordVPN's repository is affected by a permission issue in init script and systemd unit files that allows any user on the system to execute arbitrary command as root.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder ## Description from ATT&CK Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. > **Jargon: Persistence** — A tactic where attacke
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Hunting for Persistence in Linux - Part 1

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Hunting for Persistence in Linux (Part 1): Auditd, Sysmon, Osquery (and Webshells) Nov 22, 2021 • Pepe Berba ### Overview of blog series Welcome to this blog series “Hunting for Persistence in Linux”! This is a series that explores methods attackers might use to maintain persis
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Persistence TryHackme Writeup

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Persistence TryHackme Writeup Room link: https://tryhackme.com/room/persistence # What is persistence? Persistence is a post-exploitation activity used by penetration testers in order to keep access to a system throughout the whole assessment and not to have to re-exploit the t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Hunting for Persistence in Linux - Part 2

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Hunting for Persistence in Linux (Part 2): Account Creation and Manipulation ### Introduction In the previous blog post, we’ve discussed how to setup auditd and sysmon so that we can start hunting for persistence techniques in linux hosts. Specifically, we discussed some ways w
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Hunting for Persistence in Linux - Part 4

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Hunting for Persistence in Linux (Part 4): Initialization Scripts and Shell Configuration Feb 6, 2022 Pepe Berba ### Introduction In this blogpost, we’ll be discussing some scripts that attackers can install or modify that will execute on boot or logon. This is special files ou
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Hunting for Persistence in Linux - Part 5

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Hunting for Persistence in Linux (Part 5): Systemd Generators Feb 7, 2022 ### Introduction In this blogpost, we’re discussing a specific persistence technique that I haven’t read anywhere else. Because of this, it seemed appropriate for it to have its own post. The topics discu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
