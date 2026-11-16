# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cloud-incident-response-identity-containment`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Dolibarr 7.0.0 is affected by: Cross Site Request Forgery (CSRF). The impact is: allow malitious htm

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Dolibarr 7.0.0 is affected by: Cross Site Request Forgery (CSRF). The impact is: allow malitious html to change user password, disable users and disable password encryptation. The component is: Functi - **CVE**: CVE-2019-1010054 - **Exploit Type**: InTheWild - **Exploit ID**: I
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: The Disable User Login WordPress plugin through 1.0.1 does not have authorisation and CSRF checks wh

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # The Disable User Login WordPress plugin through 1.0.1 does not have authorisation and CSRF checks when updating its settings, allowing unauthenticated attackers to block (or unblock) users at will. - **CVE**: CVE-2022-2350 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: org.xwiki.platform:xwiki-platform-user-profile-ui is missing authorization to enable or disable user

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # org.xwiki.platform:xwiki-platform-user-profile-ui is missing authorization to enable or disable users. Any user (logged in or not) with access to the page XWiki.XWikiUserProfileSheet can enable or dis - **CVE**: CVE-2022-41930 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Missing Authorization to enable or disable users in org.xwiki.platform:xwiki-platform-user-profile-u

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact Any user (logged in or not) with access to the page XWiki.XWikiUserProfileSheet can enable or disable any user profile. This might allow to a disabled user to re-enable themselves, or to an attacker to disable any user of the wiki. ### Patches The problem has been patc
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
