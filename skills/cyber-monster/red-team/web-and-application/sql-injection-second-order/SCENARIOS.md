# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`sql-injection-second-order`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Missing rate limit for current password field (Password Change) Account Takeover

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnerability: Missing Rate Limit for Current Password field (Password Change) Account Takeover Steps to reproduce the bug: 1)Go to Profile > Password. Enter any (wrong password) In current password filed. 2)Now enter the new password and Turn the Intercept ON.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Weak Session ID Implementation - No Session change on Password change

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** [Weak session id implementation] **Description:** [Unikrn does not change session id after password is changed. Reusing same session ids, after password is changed is highly risky.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Weblate Doesn't Invalidate API Token on Password Change

- **Provenance:** Source: `CYBER_CPT/gh_security_lab`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Impact When a user changes their password, browser sessions are correctly invalidated via 'cycle_session_keys()', but DRF API tokens ('wlu_*' prefix) stored in 'authtoken_token' are not revoked.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Second Order SQL-Injection on HTB Nightmare

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-89`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Nightmare just retired, and it was an insanely difficult box. Rather than do a full walkthrough, I wanted to focus on a write-up of the second-order SQL injection necessary as a first step for this host. ## Second Order SQL Injection In a typical SQL Injection, user input is used
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: listmonk's active sessions remain valid after password reset and password change

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-89`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary A session management vulnerability allows previously issued authenticated sessions to remain valid after sensitive account security changes, specifically password reset and password change. As a result, an attacker who has already obtained a valid session cookie can r
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: NetRisk 1.9.7 - Remote Password Change

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-89`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** Skip to content # Teddy Heinen About Tags # Automatic Exploit Generation 2 ' Now with printf! By Tristan (@trab on discord) nc pwn.utctf.live 5002 ' binary 1 ![\\"\\"] (\\"/uctf-2022/angr_simp.png\\"/) I really like automatic exploit generation. I did the one in last year\'s U
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Brother MFC-J6520DW - Authentication Bypass / Password Change

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-89`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** For these purposes, will work well [RsaCtfTool] (https://github.com/sourcekris/RsaCtfTool) ' cd /opt/RsaCtfTool ./[RsaCtfTool.py] (http://RsaCtfTool.py) --publickey /media/DATA/CTF/yubitsec/RSA\_I/RSA/Part1/PublicKey1.pem --private --uncipher /media/DATA/CTF/yubitsec/RSA\_I/RSA
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Brother MFC-J6520DW - Authentication Bypass / Password Change

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-89`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Brother MFC-J6520DW - Authentication Bypass / Password Change EKU-ID: 46061 CVE: CVE-2017-7588 Author: Patryk Bogdan Published: 2017-04-11 'php <?php /* # Title: Brother Devices Web Auth Bypass / Change Password Exploit # Vendor: Brother (http://www.brother.com/) # Affected m
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
