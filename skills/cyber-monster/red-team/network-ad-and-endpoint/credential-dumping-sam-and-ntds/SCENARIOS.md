# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`credential-dumping-sam-and-ntds`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Eighteen

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Eighteen is a Windows Server 2025 assume-breach box starting with MSSQL credentials. I'll use MSSQL login impersonation to access the financial planner database and recover a Werkzeug PBKDF2 hash for the web admin. After cracking the hash and spraying the password against domain
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Cicada

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Cicada is a pure easy Windows Active Directory box. I’ll start enumerating SMB shares to find a new hire welcome note with a default password. I’ll RID-cycle to get a list of usernames, and spray that password to find a user still using it. With a valid user I can query LDAP to f
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: Kotarak

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Kotarak starts with an SSRF that allows me to find additional webservers on ports only listening on localhost. I'll use that to leak a Tomcat config with username and password, and upload a malicious war to get a shell. From there, I can access files from an old Windows pentest t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: APT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** APT was a clinic in finding little things to exploit in a Windows host. I’ll start with access to only RPC and HTTP, and the website has nothing interesting. I’ll use RPC to identify an IPv6 address, which when scanned, shows typical Windows DC ports. Over SMB, I’ll pull a zip co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
