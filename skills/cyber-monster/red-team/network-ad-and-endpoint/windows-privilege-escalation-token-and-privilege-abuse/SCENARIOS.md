# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-privilege-escalation-token-and-privilege-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Breach

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Breach is a Windows domain controller box. I'll start by using guest access to a writable SMB share to drop ntlm_theft lure files, capturing a NetNTLMv2 hash for a domain user with Responder. After cracking that hash, I'll use BloodHound to find a Kerberoastable MSSQL service acc
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Media

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Media starts with a PHP site on Windows that takes video uploads. I'll use a wax file to leak a net-NTLMv2 hash, and then crack it to get SSH access to the host. I'll understand how the webserver is writing the files to the filesystem, and use a junction point link to have it wri
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Mailing

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Mailing is a mail server company that offers webmail powered by hMailServer. There’s a PHP site which has a file read / directory traversal vulnerability. I’ll leak the hMailServer config, and crack the password hash to get valid credentials. ## Recon ### nmap 'nmap' finds many o
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Visual

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Visual is all about abusing a Visual Studio build process. There’s a website that takes a hosted Git URL and loads a Visual Studio project from the URL and compiles it. I’ll stand up a Gitea server in a container and host a project with a pre-build action that runs a command and
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Haze

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Haze is built around an instance of Splunk Enterprise. I’ll start by exploiting a directory traversal / file read in Splunk that allows me to leak configuration files that container encrypted passwords. I’ll exfil the key and decrypt them, finding a password that’s reused by a us
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
