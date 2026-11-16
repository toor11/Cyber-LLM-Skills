# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`http-request-smuggling-http2-desync`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-444`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: ServMon

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-444`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ServMon was an easy Windows box that required two exploits. There’s a hint in the anonymous FTP as to the location of a list of passwords. I can use a directory traversal bug in a NVMS 1000 web instance that will allow me to leak those passwords, and use one of them over SSH to g
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: BigHead

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-444`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** BigHead required you to earn your 50 points. The enumeration was a ton. There was an really fun but challenging buffer overflow to get initial access. Then some pivoting across the same host using SSH and the a php vulnerability. And then finding a hidden KeePass database with a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Anubis

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-444`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Anubis starts simply enough, with a ASP injection leading to code execution in a Windows Docker container. In the container I’ll find a certificate request, which leaks the hostname of an internal web server. That server is handling software installs, and by giving it my IP, I’ll
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Laser

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-444`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Laser starts without the typical attack paths, offering only SSH and two unusual ports. One of those is a printer, which gives the opportunity to leak data including a print job and the memory with the encryption key for that job. The PDF gives details of how the second port work
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Intense

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-444`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Intense presented some cool challenges. I'll start by finding a SQL injection vulnerability into an sqlite database. I'm able to leak the admin hash, but not crack it. Using the source code for the site, I'll see that if I can use a hash extension attack, I can use the hash trick
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
