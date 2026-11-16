# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`oauth-oidc-misconfiguration-token-and-scope-abuse`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Az - Primary Refresh Token (PRT)

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-601`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # Az - Primary Refresh Token (PRT) ## What is a Primary Refresh Token (PRT)? A **Primary Refresh Token (PRT)** is a long-lived refresh token used in Azure AD (Entra ID) authentication, analogous to a Kerberos TGT. It is issued upon user login on an Azure AD-joined device and can
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Nhost Leaks Refresh Tokens via URL Query Parameter in OAuth Provider Callback

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-601`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Refresh Token Leaked via URL Query Parameter in OAuth Provider Callback ## Summary The auth service's OAuth provider callback flow places the refresh token directly into the redirect URL as a query parameter. Refresh tokens in URLs are logged in browser history, server access l
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: openssl-encrypt accepts refresh tokens as URL query parameters causing token leakage

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-601`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary Refresh tokens are accepted as URL query parameters in the keyserver and telemetry server routes. ### Affected Code 'python # openssl_encrypt_server/modules/keyserver/routes.py:214-215 # openssl_encrypt_server/modules/telemetry/routes.py:90-91 async def refresh_toke
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: OliveTin has JWT Audience Validation Bypass in Local Key and HMAC Modes

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-601`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # OliveTin has JWT Audience Validation Bypass in Local Key and HMAC Modes OliveTin has JWT Audience Validation Bypass in Local Key and HMAC Modes - **OSV ID**: GHSA-g962-2j28-3cg9 - **CVE**: CVE-2026-30223 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H - **Published**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Primary Refresh Token Access Attempt

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-601`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Primary Refresh Token Access Attempt Indicates access attempt to the PRT resource which can be used to move laterally into an organization or perform credential theft - **Level**: N/A - **Status**: test - **Author**: Mark Morowczynski '@markmorow', Gloria Lee, '@gleeiamglo - **
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: OliveTin has JWT Audience Validation Bypass in Local Key and HMAC Modes

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-601`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary When JWT authentication is configured using either: - 'authJwtPubKeyPath' (local RSA public key), or - 'authJwtHmacSecret' (HMAC secret), the configured audience value ('authJwtAud') is not enforced during token parsing. As a result, validly signed JWT tokens with an
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
