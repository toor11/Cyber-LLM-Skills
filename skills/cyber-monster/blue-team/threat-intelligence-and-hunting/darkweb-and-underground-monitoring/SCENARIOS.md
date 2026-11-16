# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`darkweb-and-underground-monitoring`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: CVE-2022-27774: Credential leak on redirect

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2022-27774`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: curl/libcurl can be coaxed to leak user credentials to third-party host by issuing HTTP redirect to ftp:// URL. Steps To Reproduce: 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Credential leak on GitHub: https://github.com/█/█/ (Peoplesoft CRM)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Description:** hey , i found a credential leak on github https://github.com/████████/███████/blob/22dc688289fac99f█████/testsql.sh Steps To Reproduce: (Add details for how we can reproduce the issue) 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: HAPI FHIR Core has Authentication Credential Leakage via Improper URL Prefix Matching on HTTP Redire

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-200`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary 'ManagedWebAccessUtils.getServer()' uses 'String.startsWith()' to match request URLs against configured server URLs for authentication credential dispatch. Because configured server URLs (e.g., 'http://tx.fhir.org') lack a trailing slash or host boundary check, an atta
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-200`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary A previously reported issue in axios demonstrated that using protocol-relative URLs could lead to SSRF (Server-Side Request Forgery). Reference: axios/axios#6463 A similar problem that occurs when passing absolute URLs rather than protocol-relative URLs to axios has b
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HAPI FHIR Core has Authentication Credential Leakage via Improper URL Prefix Matching on HTTP Redire

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-200`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # HAPI FHIR Core has Authentication Credential Leakage via Improper URL Prefix Matching on HTTP Redirect HAPI FHIR Core has Authentication Credential Leakage via Improper URL Prefix Matching on HTTP Redirect - **OSV ID**: GHSA-fgv2-4q4g-wc35 - **CVE**: CVE-2026-34359 - **CVSS**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: FHIR Validator HTTP service has SSRF via /loadIG Chains with startsWith() Credential Leak for Authen

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-200`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # FHIR Validator HTTP service has SSRF via /loadIG Chains with startsWith() Credential Leak for Authentication Token Theft - **OSV ID**: GHSA-vr79-8m62-wh98 - **CVE**: CVE-2026-34361 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N - **Published**: 2026-03-30T17:24:10Z -
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Milesight Routers UR5X_ UR32L_ UR32_ UR35_ UR41 - Credential Leakage Through Unprotected System Logs

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-200`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Milesight Routers UR5X_ UR32L_ UR32_ UR35_ UR41 - Credential Leakage Through Unprotected System Logs / EKU-ID: 55658 / CVE: / OSVDB-ID: / / --- / --- / --- / / Author: Bipin Jitiya / Published: 2024-02-05 / Verified: Not Verified / 'python #!/usr/bin/env python3 # -*- coding:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Glances has SSRF in IP Plugin via public_api leading to credential leakage

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-200`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary A Server-Side Request Forgery (SSRF) vulnerability exists in the Glances IP plugin due to improper validation of the public_api configuration parameter. The value of public_api is used directly in outbound HTTP requests without any scheme restriction or hostname/IP va
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
