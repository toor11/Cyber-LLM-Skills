# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`detection-engineering-behaviour-to-observable`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: h3 has an observable timing discrepancy in basic auth utils

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # h3 has an observable timing discrepancy in basic auth utils - **OSV ID**: GHSA-26f5-8h2x-34xh - **CVE**: CVE-2026-33129 - **CVSS**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N - **Published**: 2026-03-18T16:17:58Z - **Modified**: 2026-03-20T21:35:11.362620Z - **Affected Packag
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: h3 has an observable timing discrepancy in basic auth utils

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary A Timing Side-Channel vulnerability exists in the 'requireBasicAuth' function due to the use of unsafe string comparison ('!=='). This allows an attacker to deduce the valid password character-by-character by measuring the server's response time, effectively bypassing
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Mojic: Observable Timing Discrepancy in HMAC Verification

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Mojic: Observable Timing Discrepancy in HMAC Verification - **OSV ID**: GHSA-wqq3-wfmp-v85g - **CVSS**: CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N - **Published**: 2026-04-16T21:10:17Z - **Modified**: 2026-04-16T21:18:26.775683Z - **Affected Packages**: mojic - **Ecosystem**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Mojic: Observable Timing Discrepancy in HMAC Verification

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary The 'CipherEngine' in Mojic v2.1.3 uses a standard equality operator ('!==') to verify the HMAC-SHA256 integrity seal during the decryption phase. This creates an Observable Timing Discrepancy (CWE-208), allowing a potential attacker to bypass the file integrity check
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Versions of the package jsrsasign before 11.0.0 are vulnerable to Observable Discrepancy via the RSA

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Versions of the package jsrsasign before 11.0.0 are vulnerable to Observable Discrepancy via the RSA PKCS1.5 or RSAOAEP decryption process. An attacker can decrypt ciphertexts by exploiting the Marvin - **CVE**: CVE-2024-21484 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Dify User Enumeration via Observable Response Discrepancy

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-778`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Dify User Enumeration via Observable Response Discrepancy / - **Template ID**: CVE-2026-28288 - **Severity**: medium - **Author**: DhiyaneshDk - **CVE**: CVE-2026-28288 - **Category**: Http - **Tags**: cve, cve2026, dify, user-enum, info-leak 'yaml id: CVE-2026-28288 info: na
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
