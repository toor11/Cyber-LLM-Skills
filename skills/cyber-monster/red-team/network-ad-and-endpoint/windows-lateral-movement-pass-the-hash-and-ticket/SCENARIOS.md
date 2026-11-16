# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-lateral-movement-pass-the-hash-and-ticket`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Pass the Hash

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Pass the Hash **ID**: T1550.002 **Type**: Technique **Tactics**: Lateral Movement **Platforms**: Windows Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Pass the Ticket

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Pass the Ticket Pass The Ticket (PTT) In the **Pass The Ticket (PTT)** attack method, attackers **steal a user's authentication ticket** instead of their password or hash values.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: T1550.003 - Use Alternate Authentication Material: Pass the Ticket

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1550.003 - Use Alternate Authentication Material: Pass the Ticket ## Description from ATT&CK Adversaries may "pass the ticket" using stolen Kerberos tickets to move laterally within an environment, bypassing normal system access controls. > **Jargon: Kerberos** — A network aut
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Pass The Hash: Privilege Escalation with Invoke-WMIExec

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Pass The Hash: Privilege Escalation with Invoke-WMIExec ## Execution If you have an NTLMv2 hash of a local administrator on a box ws01, it's possible to pass that hash and execute code with privileges of that local administrator account: 'csharp Invoke-WmiExec -target ws01 -h
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Pass the Hash with Machine$ Accounts

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Pass the Hash with Machine$ Accounts This lab looks at leveraging machine account NTLM password hashes or more specifically - how they can be used in pass the hash attacks to gain additional privileges, depending on which groups the machine is a member of (ideally administrator
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Over Pass the Hash/Pass the Key

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Over Pass the Hash/Pass the Key ## Overpass The Hash/Pass The Key (PTK) The **Overpass The Hash/Pass The Key (PTK)** attack is designed for environments where the traditional NTLM protocol is restricted, and Kerberos authentication takes precedence. This attack leverages the NT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Abusing RDP’s Remote Credential Guard with Rubeus PTT

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-269`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** ### TL;DR * Microsoft’s Remote Credential Guard (RCG) for RDP protects creds if an RDP server is compromised. * It leaves little scope for password or NTLM credential dumping when a user connects to the server. * It does however introduce workstation attack vectors. * Abusing a u
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: T1550.002 - Use Alternate Authentication Material: Pass the Hash

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1550.002 - Use Alternate Authentication Material: Pass the Hash ## Description from ATT&CK > Adversaries may “pass the hash” using stolen password hashes to move laterally within an environment, bypassing normal system access controls. Pass the hash (PtH) is a method of authen
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
