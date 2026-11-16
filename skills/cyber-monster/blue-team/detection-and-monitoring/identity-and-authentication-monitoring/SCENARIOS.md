# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`identity-and-authentication-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Taylor has race condition in /get-patch that allows purchase token replay

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Taylor has race condition in /get-patch that allows purchase token replay - **OSV ID**: GHSA-vh5j-5fhq-9xwg - **Published**: 2025-06-27T22:06:48Z - **Modified**: 2025-06-30T12:53:28Z - **Affected Packages**: taylored - **Ecosystem**: npm I was looking at the recent fix and you
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: OpenID Connect nonce generated but never validated — ID token replay attack

- **Provenance:** Source: `CYBER_CPT/gh_security_lab` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_security_lab (en)
- **Root Cause / Analysis:** ### Summary The 'roadiz/openid' package generates an OIDC nonce in 'OAuth2LinkGenerator::generate()' and includes it in the authorization request sent to the identity provider, but **never stores it** and **never validates it** on the callback. The 'OpenIdJwtConfigurationFactory'
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Impossible Travel

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-778`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Impossible Travel Identifies user activities originating from geographically distant locations within a time period shorter than the time it takes to travel from the first location to the second. - **Level**: N/A - **Status**: test - **Date**: 2023-09-03 - **Category**: Cloud #
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Taylor has race condition in /get-patch that allows purchase token replay

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** Hi team, I was looking at the recent fix and you limited the exploitability of race conditions but unfortunately it is still possible to exploit the issue since two requests happening at the exact same time will still go through. You should be able to completely fix the race cond
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Microsoft 365 - Impossible Travel Activity

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-778`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Microsoft 365 - Impossible Travel Activity Detects when a Microsoft Cloud App Security reported a risky sign-in attempt due to a login associated with an impossible travel. - **Level**: N/A - **Status**: test - **Author**: Austin Songer @austinsonger - **Date**: 2020-07-06 - **
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Mattermost has an Invite Token Replay Vulnerability via Channel Membership Manipulation

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Mattermost has an Invite Token Replay Vulnerability via Channel Membership Manipulation Mattermost has an Invite Token Replay Vulnerability via Channel Membership Manipulation - **OSV ID**: GHSA-x3r8-2hmh-89f5 - **CVE**: CVE-2025-13324 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
