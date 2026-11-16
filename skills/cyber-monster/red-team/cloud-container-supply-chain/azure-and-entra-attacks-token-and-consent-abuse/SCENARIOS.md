# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`azure-and-entra-attacks-token-and-consent-abuse`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Az - Primary Refresh Token (PRT)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Az - Primary Refresh Token (PRT) What is a Primary Refresh Token (PRT)? A **Primary Refresh Token (PRT)** is a long-lived refresh token used in Azure AD (Entra ID) authentication, analogous to a Kerberos TGT.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Az - Primary Refresh Token (PRT)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-269`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Az - Primary Refresh Token (PRT) ## What is a Primary Refresh Token (PRT)? A **Primary Refresh Token (PRT)** is a long-lived refresh token used in Azure AD (Entra ID) authentication, analogous to a Kerberos TGT. It is issued upon user login on an Azure AD-joined device and can
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Dynamic Device Code Phishing

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-269`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** 1. **Analyze the Request:** * **Role:** Master cybersecurity educator. * **Target Audience:** Bright but novice security learner. * **Goal:** Deeply elucidate, make complex intuitive, make implicit explicit. * **Unbreakable Rules:** * (a) Technical Correctness: Preserve all detai
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Six Accounts, One Actor: Inside the prt-scan Supply Chain Campaign

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-269`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** On April 2, 2026, security researcher Charlie Eriksen publicly identified an automated campaign exploiting GitHub's 'pull_request_target' workflow trigger. The attacker, operating under the account 'ezmtebo', opened over 475 malicious PRs in 26 hours targeting repositories belong
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Original Sin of SSO macOS PRT Cookie Theft & Entra ID Persistence via Device Forgery

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-269`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** # Original Sin of SSO: macOS PRT Cookie Theft & Entra ID Persistence via Device Forgery Shang-De 'John' Jiang, Kazma Ye, Echo Lee ## SSO Token Generation in Windows OS LSASS -> Cloud AP: aadcloudap -> CreateSSOCookie TPM -> PRT -> Session Key ## PRT Can Exchange Everything We Wan
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Primary Refresh Token Access Attempt

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-269`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Primary Refresh Token Access Attempt Indicates access attempt to the PRT resource which can be used to move laterally into an organization or perform credential theft - **Level**: N/A - **Status**: test - **Author**: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo - **
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Nhost Leaks Refresh Tokens via URL Query Parameter in OAuth Provider Callback

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-269`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Refresh Token Leaked via URL Query Parameter in OAuth Provider Callback ## Summary The auth service's OAuth provider callback flow places the refresh token directly into the redirect URL as a query parameter. Refresh tokens in URLs are logged in browser history, server access l
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
