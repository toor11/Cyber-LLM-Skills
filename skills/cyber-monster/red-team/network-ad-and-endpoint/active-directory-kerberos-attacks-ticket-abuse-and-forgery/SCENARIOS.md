# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-kerberos-attacks-ticket-abuse-and-forgery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Pass the Ticket

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Pass the Ticket **ID**: T1550.003 **Type**: Technique **Tactics**: Lateral Movement **Platforms**: Windows Adversaries may “pass the ticket” using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Pass the Ticket

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Pass the Ticket Pass The Ticket (PTT) In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Anubis

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Anubis starts simply enough, with a ASP injection leading to code execution in a Windows Docker container. In the container I’ll find a certificate request, which leaks the hostname of an internal web server. That server is handling software installs, and by giving it my IP, I’ll
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Rubeus

- **Provenance:** Source: `CYBER_CPT/h4cker` | CWE: `CWE-269`
- **Context / Surface:** Source: h4cker (en)
- **Root Cause / Analysis:** # Rubeus ---- Rubeus is a C# toolset for raw Kerberos interaction and abuses. It is **heavily** adapted from [Benjamin Delpy] (https://twitter.com/gentilkiwi)'s [Kekeo] (https://github.com/gentilkiwi/kekeo/) project (CC BY-NC-SA 4.0 license) and [Vincent LE TOUX] (https://twitter.co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Rubeus Readme

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** Ticket requests and renewals: Retrieve a TGT based on a user password/hash, optionally saving to a file or applying to the current logon session or a specific LUID: ' Rubeus.exe asktgt /user:USER </password:PASSWORD [/enctype:DES/RC4/AES128/AES256] / /des:HASH / /rc4:HASH / /ae
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: University

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** University is a monster insane level machine. I'll start with a website and exploit a CVE in the process of generating a PDF copy of my profile to get a shell on the host. I'll find the same user's creds in a PowerShell script, and use them to log into not only this host, but two
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
