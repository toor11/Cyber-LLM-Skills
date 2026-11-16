# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`network-protocol-attacks-name-resolution-poisoning`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Anubis

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Anubis starts simply enough, with a ASP injection leading to code execution in a Windows Docker container. In the container I’ll find a certificate request, which leaks the hostname of an internal web server. That server is handling software installs, and by giving it my IP, I’ll
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: RE

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** RE was a box I was really excited about, and I was crushed when the final privesc didn’t work on initial deployment. Still, it got patched, and two unintended paths came about as well, and everything turned out ok. I’ll approach this write-up how I expected people to solve it, an
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Sizzle

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** I loved Sizzle. It was just a really tough box that reinforced Windows concepts that I hear about from pentesters in the real world. I'll start with some SMB access, use a .scf file to capture a users NetNTLM hash, and crack it to get creds. From there I can create a certificate
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Tier 1 — Hack The Box — Mission: Responder

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-284`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Tier 1 — Hack The Box — Mission: Responder In today’s Hack The Box challenge, “Responder,” we will explore vulnerabilities within a web service to retrieve a hash from a Windows server. By leveraging these weaknesses, we’ll use tools to crack the hash and gain access to the ser
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: APT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-284`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** APT was a clinic in finding little things to exploit in a Windows host. I’ll start with access to only RPC and HTTP, and the website has nothing interesting. I’ll use RPC to identify an IPv6 address, which when scanned, shows typical Windows DC ports. Over SMB, I’ll pull a zip co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
