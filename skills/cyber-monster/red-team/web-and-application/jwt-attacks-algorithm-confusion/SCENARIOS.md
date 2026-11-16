# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`jwt-attacks-algorithm-confusion`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Another JWT Algorithm Confusion Vulnerability: CVE-2024-54150

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-347`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** # Another JWT Algorithm Confusion Vulnerability: CVE-2024-54150 Recently, I was in Brisbane to give a talk on JWT algorithm confusion vulnerabilities. During a conversation with my friend Luke (whose blog you should definitely check out, especially if you are into [Ruby Security]
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: json-web-token library is vulnerable to a JWT algorithm confusion attack

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # json-web-token library is vulnerable to a JWT algorithm confusion attack - **OSV ID**: GHSA-4xw9-cx39-r355 - **CVE**: CVE-2023-48238 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N - **Published**: 2023-11-17T22:48:15Z - **Modified**: 2023-11-20T22:06:44Z - **Affected
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: pREST vulnerable to jwt bypass + sql injection

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # pREST vulnerable to jwt bypass + sql injection - **OSV ID**: GHSA-wm25-j4gw-6vr3 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - **Published**: 2024-07-30T15:04:26Z - **Modified**: 2024-08-07T14:16:28Z - **Affected Packages**: github.com/prest/prest - **Ecosystem**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: lightrag-hku: JWT Algorithm Confusion Vulnerability

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-347`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The LightRAG API is vulnerable to a JWT algorithm confusion attack where an attacker can forge tokens by specifying 'alg': 'none' in the JWT header. Since the 'jwt.decode()' call does not explicitly deny the 'none' algorithm, a crafted token without a signature will be
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: json-web-token library is vulnerable to a JWT algorithm confusion attack

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-347`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary The json-web-token library is vulnerable to a JWT algorithm confusion attack. ### Details On line 86 of the 'index.js' file, the algorithm to use for verifying the signature of the JWT token is taken from the JWT token, which at that point is still unverified and thus
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: fast-jwt: Incomplete fix for CVE-2023-48223: JWT Algorithm Confusion via Whitespace-Prefixed RSA Pub

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # fast-jwt: Incomplete fix for CVE-2023-48223: JWT Algorithm Confusion via Whitespace-Prefixed RSA Public Key - **OSV ID**: GHSA-mvf2-f6gm-w987 - **CVE**: CVE-2026-34950 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N - **Published**: 2026-04-02T20:37:54Z - **Modified**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
