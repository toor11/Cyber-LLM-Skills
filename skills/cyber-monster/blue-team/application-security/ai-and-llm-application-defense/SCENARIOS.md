# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ai-and-llm-application-defense`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: The fileview package v0.1.6 has inadequate output encoding and escaping, which leads to a stored Cro

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # The fileview package v0.1.6 has inadequate output encoding and escaping, which leads to a stored Cross-Site Scripting (XSS) vulnerability in files it serves. - **CVE**: CVE-2019-15602 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-7f968cf6d4de580025dcc2c5592fdef4 - *
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Unvalidated input and lack of output encoding in the Envira Gallery Lite WordPress plugin, versions

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Unvalidated input and lack of output encoding in the Envira Gallery Lite WordPress plugin, versions before 1.8.3.3, did not properly sanitise the images metadata (namely title) before outputting them - **CVE**: CVE-2021-24126 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Unvalidated input and lack of output encoding in the WP Shieldon WordPress plugin, version 1.6.3 and

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Unvalidated input and lack of output encoding in the WP Shieldon WordPress plugin, version 1.6.3 and below, leads to Unauthenticated Reflected Cross-Site Scripting (XSS) when the CAPTCHA page is shown - **CVE**: CVE-2021-24124 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Unvalidated input and lack of output encoding in the Team Members WordPress plugin, versions before

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Unvalidated input and lack of output encoding in the Team Members WordPress plugin, versions before 5.0.4, lead to Cross-site scripting vulnerabilities allowing medium-privileged authenticated attacke - **CVE**: CVE-2021-24128 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Unvalidated input and lack of output encoding in the Themify Portfolio Post WordPress plugin, versio

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Unvalidated input and lack of output encoding in the Themify Portfolio Post WordPress plugin, versions before 1.1.6, lead to Stored Cross-Site Scripting (XSS) vulnerabilities allowing low-privileged u - **CVE**: CVE-2021-24129 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Unvalidated input and lack of output encoding in the WP Customer Reviews WordPress plugin, versions

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Unvalidated input and lack of output encoding in the WP Customer Reviews WordPress plugin, versions before 3.4.3, lead to multiple Stored Cross-Site Scripting vulnerabilities allowing remote attackers - **CVE**: CVE-2021-24135 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
