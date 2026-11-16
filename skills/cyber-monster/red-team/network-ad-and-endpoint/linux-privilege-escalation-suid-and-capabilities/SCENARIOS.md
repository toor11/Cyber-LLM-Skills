# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`linux-privilege-escalation-suid-and-capabilities`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Lightweight — HackTheBox

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Lightweight — HackTheBox LightWeight se trata de una máquina CentOS creada por 0xEA31. Nos indican cómo acceder directamente a la máquina. La clave de esta máquina son las linux capabilities. Primero tendremos permisos para correr tcpdump como root, por lo que capturaremos tráfico hasta encontrar un password.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: HTB: RedCross

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** RedCross was a maze, with a lot to look at and multiple paths at each stage. I'll start by enumerating a website, and showing two different ways to get a cookie to use to gain access to the admin panel. Then, I'll get a shell on the box as penelope, either via an exploit in the H
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Curling

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Curling was a solid box easy box that provides a chance to practice some basic enumeration to find a password, using that password to get access to a Joomla instance, and using the access to get a shell. With a shell, I'll find a compressed and encoded backup file, that after a b
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Linux Capabilities

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Linux Capabilities Linux capabilities divide **root privileges into smaller, distinct units**, allowing processes to have a subset of privileges. This minimizes the risks by not granting full root privileges unnecessarily. ### The Problem: - Normal users have limited permission
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Shrek

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Shrek is another 2018 HackTheBox machine that is more a string of challenges as opposed to a box. I’ll find an uploads page in the website that doesn’t work, but then also find a bunch of malware (or malware-ish) files in the uploads directory. One of them contains a comment abou
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Sneaky

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Sneaky presented a website that after some basic SQL injection, leaked an SSH key. But SSH wasn’t listening. At least not on IPv4. I’ll show three ways to find the IPv6 address of Sneaky, and then SSH using that address to get user. For root, there’s a simple buffer overflow with
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: Charon

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Another 2017 box, but this one was a lot of fun. There’s an SQL injection the designed to break sqlmap (I didn’t bother to go into sqlmap, but once I finished saw from others). Then there’s a file upload, some crypto, and a command injection. I went into good detail on the manual
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
