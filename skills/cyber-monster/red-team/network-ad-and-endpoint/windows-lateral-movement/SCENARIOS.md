# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-lateral-movement`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Hathor

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Hathor is an insane box that lives up to the difficulty. I’ll start with some default creds logging into a mojoPortal website. From there, I’ll figure out how to upload a webshell, and copy it to get the right extension. All my efforts to get a shell are blocked, and I’ll do a de
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Sauna

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Sauna was a neat chance to play with Windows Active Directory concepts packaged into an easy difficulty box. I’ll start by using a Kerberoast brute force on usernames to identify a handful of users, and then find that one of them has the flag set to allow me to grab their hash wi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Jeeves

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Jeeves was first released in 2017, and I first solved it in 2018. Four years later, it’s been an interesting one to revisit. Some of the concepts seem not that new and exciting, but it’s worth remembering that Jeeves was the first to do them. I’ll start with a webserver and find
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Anubis

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Anubis starts simply enough, with a ASP injection leading to code execution in a Windows Docker container. In the container I’ll find a certificate request, which leaks the hostname of an internal web server. That server is handling software installs, and by giving it my IP, I’ll
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
