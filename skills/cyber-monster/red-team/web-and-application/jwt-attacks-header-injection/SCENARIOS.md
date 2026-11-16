# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`jwt-attacks-header-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Authlib JWS JWK Header Injection: Signature Verification Bypass

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-347`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Description ### Summary A JWK Header Injection vulnerability in 'authlib's JWS implementation allows an unauthenticated attacker to forge arbitrary JWT tokens that pass signature verification. When 'key=None' is passed to any JWS deserialization function, the library extracts
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Authlib JWS JWK Header Injection: Signature Verification Bypass

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Authlib JWS JWK Header Injection: Signature Verification Bypass - **OSV ID**: GHSA-wvwj-cvrp-7pv5 - **CVE**: CVE-2026-27962 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N - **Published**: 2026-03-16T15:17:15Z - **Modified**: 2026-04-21T08:11:07.942106708Z - **Affected
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: JWT Kid Injection

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-347`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **JWT Kid Injection** exploits the "kid" (Key ID) header parameter when it's used unsafely to retrieve verification keys. If the kid value is used directly in SQL queries, file paths, or command execution, attackers can manipulate it for injection attacks. ### How It Works The ki
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: JWT kid Injection

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-347`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** # JWT kid Injection This course explores the exploitation of a vulnerability in the use of JSON Web Tokens (JWT) for authentication, specifically focusing on manipulating the 'kid' parameter to gain administrator access. This exercise was originally a challenge in the complex and
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: jose vulnerable to untrusted JWK header key acceptance during signature verification

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # jose vulnerable to untrusted JWK header key acceptance during signature verification jose vulnerable to untrusted JWK header key acceptance during signature verification - **OSV ID**: GHSA-vm9r-h74p-hg97 - **CVE**: CVE-2026-34240 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: jose vulnerable to untrusted JWK header key acceptance during signature verification

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-347`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact A vulnerability in 'jose' versions up to and including '0.3.5' could allow an unauthenticated, remote attacker to forge valid JWS/JWT tokens by using a key embedded in the JOSE header ('jwk'). The vulnerability exists because key selection could treat header-provided '
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
