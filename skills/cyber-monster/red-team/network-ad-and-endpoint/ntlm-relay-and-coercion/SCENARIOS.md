# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ntlm-relay-and-coercion`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: LDAP Signing & Channel Binding Hardening

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** LDAP Signing & Channel Binding Hardening {{#include ../../banners/hacktricks-training.md}} Why it matters LDAP relay/MITM lets attackers forward binds to Domain Controllers to obtain authenticated contexts.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** SCCM Management Point NTLM Relay to SQL – OSD Policy Secret Extraction {{#include ../../banners/hacktricks-training.md}} TL;DR By coercing a **System Center Configuration Manager (SCCM) Management Point (MP)** to authenticate over SMB/RPC and **relaying** that NTLM machine account to the **site...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-294`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # ADCS + PetitPotam NTLM Relay: Obtaining krbtgt Hash with Domain Controller Machine Certificate This is a quick lab to familiarize with an Active Directory Certificate Services (ADCS) + PetitPotam + NLTM Relay technique that allows attackers, given ADCS is misconfigured (which i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: DarkZero

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkZero is an assume breach Windows box with two forests connected by a bidirectional cross-forest trust. Starting with given credentials, I’ll enumerate MSSQL on DC01 and find a linked server to DC02 in the other forest where the mapped account is sysadmin. I’ll enable xp_cmdsh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB: DarkCorp

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** DarkCorp lives up to its insane difficulty, with three hosts, including a Windows AD domain, and starts with a Debian web/mail server. I’ll exploit an XSS in RoundCube to get access to the admin’s emails, leaking a private subdomain. I’ll reset the admin’s password and get into t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: APT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** APT was a clinic in finding little things to exploit in a Windows host. I’ll start with access to only RPC and HTTP, and the website has nothing interesting. I’ll use RPC to identify an IPv6 address, which when scanned, shows typical Windows DC ports. Over SMB, I’ll pull a zip co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Internal - NTLM Relay

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-294`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Internal - NTLM Relay NTLMv1 and NTLMv2 can be relayed to connect to another machine. / Hash / Hashcat / Attack method / /-----------------------/---------/----------------------/ / LM / '3000' / crack/pass the hash / / NTLM/NTHash / '1000' / crack/pass the hash / / NTLMv1/Net-
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: University

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-294`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** University is a monster insane level machine. I'll start with a website and exploit a CVE in the process of generating a PDF copy of my profile to get a shell on the host. I'll find the same user's creds in a PowerShell script, and use them to log into not only this host, but two
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
