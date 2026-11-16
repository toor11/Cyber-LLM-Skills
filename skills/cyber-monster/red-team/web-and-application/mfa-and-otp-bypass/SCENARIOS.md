# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`mfa-and-otp-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: 2FA bypass by sending blank code

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** █████████. This is a failure in null check of the entered code. In simple terms, the 2FA while logging in can be bypassed by sending a blank code. This could be because of incorrect comparison of entered code with true code.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Information disclosure -> 2fa bypass -> POST exploitation

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Greetings! So i was testing algolia.com. Impressed to find out that there are mitigations in place to prevent POST exploitation such as : When 2fa is enabled we need "old password" to update following things : - To update the password - To disable the 2fa, etc (might more...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Authorization bypass using login by phone option+horizontal escalation possible on Grab Android App

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Description:** After my previous report about 2FA bypass on the Profile Edit endpoint i was interested to find enpoint, which will allow me horizontal privileges escalation.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Bypass Email Verification in Customer Portal

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi team hope you doing well :) i found a vulnerability [ OTP Bypass ] on [ https://portal.test.cloud.mattermost.com ] . Summery : I was able to use the otp that was sent to victim email and i used it in the attacker's email verify .when i tried this issue first time the server...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Az - Conditional Access Policies & MFA Bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-287`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Az - Conditional Access Policies & MFA Bypass ## Basic Information Azure Conditional Access policies are rules set up in Microsoft Azure to enforce access controls to Azure services and applications based on certain **conditions**. These policies help organizations secure their
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: 2FA/MFA/OTP Bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-287`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # 2FA/MFA/OTP Bypass ## Enhanced Two-Factor Authentication Bypass Techniques ### Direct Endpoint Access To bypass 2FA, access the subsequent endpoint directly, knowing the path is crucial. If unsuccessful, alter the **Referrer header** to mimic navigation from the 2FA verificatio
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: From Misconfigured Spring Boot Actuator to SharePoint Exfiltration: How Stolen Credentials Bypass MF

- **Provenance:** Source: `CYBER_CPT/trend_micro_research` | CWE: `CWE-287`
- **Context / Surface:** Source: trend_micro_research (en)
- **Root Cause / Analysis:** # From Misconfigured Spring Boot Actuator to SharePoint Exfiltration: How Stolen Credentials Bypass MFA Not every cloud breach starts with malware or a zero-day. In this incident, attackers discovered an exposed Spring Boot Actuator endpoint, harvested credentials from leaked con
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: How to Test Adversary-in-the-Middle Without Hacking Tools

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-287`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # How to Test Adversary-in-the-Middle Without Hacking Tools *This webcast originally aired on March 13, 2025.* In this video, Michael Allen discusses how to test Adversary-in-the-Middle attacks without using hacking tools. He delves into the intricacies of credential harvesting,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
