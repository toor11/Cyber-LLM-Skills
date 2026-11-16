# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cross-site-scripting-mutation`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: SiYuan has a SVG Sanitizer Bypass via Whitespace in 'javascript:' URI — Unauthenticated XSS

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-79`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # SVG Sanitizer Bypass via Whitespace in 'javascript:' URI — Unauthenticated XSS ## Summary SiYuan's SVG sanitizer ('SanitizeSVG') checks 'href' attributes for the 'javascript:' prefix using 'strings.HasPrefix()'. However, inserting ASCII tab ('&#9;'), newline ('&#10;'), or carri
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: SiYuan has a SVG Sanitizer Bypass via '' Element — Unauthenticated XSS

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-79`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # SiYuan has a SVG Sanitizer Bypass via '' Element — Unauthenticated XSS - **OSV ID**: GHSA-5hc8-qmg8-pw27 - **CVE**: CVE-2026-31807 - **Published**: 2026-03-10T23:49:23Z - **Modified**: 2026-03-23T04:56:05.095882656Z - **Affected Packages**: github.com/siyuan-note/siyua
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: SiYuan has a SVG Sanitizer Bypass via Whitespace in 'javascript:' URI — Unauthenticated XSS

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-79`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # SiYuan has a SVG Sanitizer Bypass via Whitespace in 'javascript:' URI — Unauthenticated XSS - **OSV ID**: GHSA-pmc9-f5qr-2pcr - **CVE**: CVE-2026-31809 - **Published**: 2026-03-10T23:57:56Z - **Modified**: 2026-03-23T04:56:03.396482991Z - **Affected Packages**: github.com/siyua
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: phpMyFAQ: SVG Sanitizer Bypass via HTML Entity Encoding Leads to Stored XSS and Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-79`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # phpMyFAQ: SVG Sanitizer Bypass via HTML Entity Encoding Leads to Stored XSS and Privilege Escalation - **OSV ID**: GHSA-5crx-pfhq-4hgg - **CVE**: CVE-2026-34974 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N - **Published**: 2026-04-01T23:42:47Z - **Modified**: 2026-0
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Rack's greedy multipart boundary parsing can cause parser differentials and WAF bypass.

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-79`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary 'Rack::Multipart::Parser' extracts the 'boundary' parameter from 'multipart/form-data' using a greedy regular expression. When a 'Content-Type' header contains multiple 'boundary' parameters, Rack selects the last one rather than the first. In deployments where an upst
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: JustHTML Affected by Mutation XSS via Literal Text Serialization in Raw Text Elements (style/script)

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-79`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary Sanitized DOM trees can be unsafe to serialize when a custom policy allows raw-text elements such as '' or ''. The issue affects DOM trees that are constructed or modified programmatically and then passed through 'sanitize_dom()' with a policy that keeps
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
