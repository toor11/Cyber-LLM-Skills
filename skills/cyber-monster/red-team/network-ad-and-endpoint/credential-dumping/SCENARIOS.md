# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`credential-dumping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HackTheBox Sauna Walkthrough

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox Sauna Walkthrough Explore ‘Sauna,’ a challenging AD-based machine, in this HTB walkthrough. Learn user enumeration, ASREProasting, Kerberoasting, and credential dumping techniques.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: Dumping Lsass without Mimikatz with MiniDumpWriteDump

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-522`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Dumping Lsass without Mimikatz with MiniDumpWriteDump This lab explores multiple ways of how we can write a simple 'lsass' process dumper using 'MiniDumpWriteDump' API. Lsass process dumps created with 'MiniDumpWriteDump' can be loaded to mimikatz offline, where credential mate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: APT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** APT was a clinic in finding little things to exploit in a Windows host. I’ll start with access to only RPC and HTTP, and the website has nothing interesting. I’ll use RPC to identify an IPv6 address, which when scanned, shows typical Windows DC ports. Over SMB, I’ll pull a zip co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: T1003.001 - OS Credential Dumping: LSASS Memory

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-522`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1003.001 - OS Credential Dumping: LSASS Memory ## Description from ATT&CK Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS). > **Jargon: LSASS (Local Security Authority Subsystem Service
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Voleur

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Voleur is an active directory box that starts with assume breach credentials. I’ll find an Excel notebook with credentials and get a shell. I’ll find a deleted user and switch to a service account to recover it. That user can access an SMB share with a user’s home directory backu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: DarkCorp

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkCorp lives up to its insane difficulty, with three hosts, including a Windows AD domain, and starts with a Debian web/mail server. I’ll exploit an XSS in RoundCube to get access to the admin’s emails, leaking a private subdomain. I’ll reset the admin’s password and get into t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
