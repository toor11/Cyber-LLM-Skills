# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-lateral-movement-rdp-and-session-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: RDP Hijacking for Lateral Movement with tscon

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # RDP Hijacking for Lateral Movement with tscon ## Execution It is possible by design to switch from one user's desktop session to another through the Task Manager (one of the ways). Below shows that there are two users on the system and currently the administrator session is in
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Session Hijacking

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Session Hijacking In session hijacking attacks, the attacker takes advantage of insecure session identifiers, finds a way to obtain them, and uses them to authenticate to the server and impersonate the victim. Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), not
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: T1563.002 - Remote Service Session Hijacking: RDP Hijacking

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1563.002 - Remote Service Session Hijacking: RDP Hijacking ## Description from ATT&CK Adversaries may hijack a legitimate user’s remote desktop session to move laterally within an environment. > **Jargon: Lateral Movement** — The technique of moving from one compromised system
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: IceBB 1.0-RC9.2 - Blind SQL Injection / Session Hijacking

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-269`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Backend Hack The Box. Linux. Medium machine. This machine has an API where we can create a new account after some exploration. Then we can find some documentation in Swagger format where we see an endpoint to execute commands and to read files from the server. We must find the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Session Hijacking (XSS) of HTB

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Session Hijacking (XSS) of HTB Try to repeat what you learned in this section to identify the vulnerable input field and find a working XSS payload, and then use the ‘Session Hijacking’ scripts to grab the Admin’s cookie and use it in ‘login.php’ to get the flag. - Make directo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Site@School 2.4.10 - 'FCKeditor' Session Hijacking / Arbitrary File Upload

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-269`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** 7Rocky ![\\"es\\"] (\\"/images/es.png\\") ![\\"en\\"] (\\"/images/en.png\\") * CTF * HTB * IMC # Balsn CTF ## Personal write-ups from Balsn CTF challenges with nice explanations, techniques and scripts <\- OTHER CTF #### Balsn CTF - Total: 2 ![\\"Prime\\"] (\\"/images/cryptography.p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
