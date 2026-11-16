# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-kerberos-attacks-asrep-roasting`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: AS-REP Roasting

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** AS-REP Roasting **ID**: T1558.004 **Type**: Technique **Tactics**: Credential Access **Platforms**: Windows Adversaries may reveal credentials of accounts that have disabled Kerberos preauthentication by Password Cracking Kerberos messages.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: TryHackMe Attacking Kerberos — Task 5 AS-REP Roasting w/ Rubeus

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe Attacking Kerberos — Task 5 AS-REP Roasting w/ Rubeus Very similar to Kerberoasting, AS-REP Roasting dumps the krbasrep5 hashes of user accounts that have Kerberos pre-authentication disabled.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: HTB: Sauna

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Sauna was a neat chance to play with Windows Active Directory concepts packaged into an easy difficulty box. I’ll start by using a Kerberoast brute force on usernames to identify a handful of users, and then find that one of them has the flag set to allow me to grab their hash wi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Roasting - ASREP Roasting

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Roasting - ASREP Roasting > If a domain user does not have Kerberos preauthentication enabled, an AS-REP can be successfully requested for the user, and a component of the structure can be cracked offline a la kerberoasting **Requirements**: * Accounts with the attribute **DONT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Impacket Getnpusers

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** Impacket's GetNPUsers.py will attempt to harvest the non-preauth AS_REP responses for a given list of usernames. These responses will be encrypted with the user's password, which can then be cracked offline. Command Reference: Target IP: 10.10.10.1 Domain: test.local Username Lis
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Impacket Getnpusers

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** ### Source https://raw.githubusercontent.com/SecureAuthCorp/impacket/master/examples/GetNPUsers.py ' TGT will be issued but not usable without session key. The AS-REP package contains a part encrypted with the user password. ' ### Request TGT for user without PreAuthenticatio
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
