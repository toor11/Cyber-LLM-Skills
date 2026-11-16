# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cross-site-scripting-blind-and-oob-xss`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Gogs XSS allowed by stored call in PDF renderer

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-79`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary A stored XSS is present in Gogs which allows client-side Javascript code execution. ### Details Gogs Version: ' docker images REPOSITORY TAG IMAGE ID CREATED SIZE gogs/gogs latest fe92583bc4fe 10 hours ago 99.3MB ' Application version: '0.14.0+dev' Local setup usi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: alerts

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-79`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # alerts The window-name is vulnerable to DOM based cross-site scripting. - **Template ID**: window-name-domxss - **Severity**: high - **Author**: pdteam - **Category**: Headless - **Tags**: headless, xss, domxss, vuln 'yaml id: window-name-domxss info: name: window.name - DOM
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Gogs XSS allowed by stored call in PDF renderer

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-79`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Gogs XSS allowed by stored call in PDF renderer Gogs XSS allowed by stored call in PDF renderer - **OSV ID**: GHSA-xh32-cx6c-cp4v - **CVE**: CVE-2025-47943 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:L/A:N - **Published**: 2025-06-26T16:54:01Z - **Modified**: 2025-07-30T
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: CI4MS: Backup Management Full Account Takeover for All-Roles & Privilege-Escalation via Stored DOM B

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-79`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # CI4MS: Backup Management Full Account Takeover for All-Roles & Privilege-Escalation via Stored DOM Blind XSS - **OSV ID**: GHSA-85m8-g393-jcxf - **CVE**: CVE-2026-34563 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:L - **Published**: 2026-04-01T22:04:21Z - **Modified**
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Blind XSS Leading to Froxlor Application Compromise

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-79`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Description: A Stored Blind Cross-Site Scripting (XSS) vulnerability has been identified in the Failed Login Attempts Logging Feature of the Froxlor Application. Stored Blind XSS occurs when user input is not properly sanitized and is stored on the server, allowing an attacke
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Blind XSS Leading to Froxlor Application Compromise

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-79`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Blind XSS Leading to Froxlor Application Compromise Blind XSS Leading to Froxlor Application Compromise - **OSV ID**: GHSA-x525-54hf-xr53 - **CVE**: CVE-2024-34070 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H - **Published**: 2024-05-10T15:29:59Z - **Modified**: 202
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
