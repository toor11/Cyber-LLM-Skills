# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`open-redirect-allowlist-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Open Redirect Bypass

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-601`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Open Redirect Bypass - **Template ID**: open-redirect-bypass - **Severity**: medium - **Category**: Dast - **Tags**: redirect, dast, vuln 'yaml id: open-redirect-bypass info: name: Open Redirect Bypass author: ritikchaddha severity: medium metadata: max-request: 1 tags: redir
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Gradio allows an open redirect bypass via URL encoding, enabling attackers to redirect users to mali

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-601`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Gradio allows an open redirect bypass via URL encoding, enabling attackers to redirect users to malicious sites. This can lead to phishing attacks and loss of trust in the application. - **CVE**: CVE-2024-8021 - **Exploit Type**: Nuclei - **Exploit ID**: Nuclei-b153283cc20aba16
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Umbraco CMS Open Redirect Bypass Protection

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-601`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Umbraco CMS Open Redirect Bypass Protection Umbraco CMS Open Redirect Bypass Protection - **OSV ID**: GHSA-j74q-mv2c-rxmp - **CVE**: CVE-2024-34071 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N - **Published**: 2024-05-21T14:29:18Z - **Modified**: 2025-02-12T18:54:13
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Umbraco CMS Open Redirect Bypass Protection

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-601`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact Umbraco have an endpoint that is vulnerable to open redirects. The endpoint is protected so it requires the user to be signed into backoffice, before the vulnerability is exposed. ### Affected Version \>= 8.18.5, >= 10.5.0, >= 12.0.0, >= 13.0.0 ### Patches 8.18.14, 10.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
