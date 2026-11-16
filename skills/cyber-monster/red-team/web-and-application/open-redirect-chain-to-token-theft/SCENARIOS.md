# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`open-redirect-chain-to-token-theft`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Phalcon Framework - Source Code Leakage

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-601`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Phalcon Framework - Source Code Leakage Phalcon Framework source code was discovered. - **Template ID**: phalcon-framework-source - **Severity**: high - **Author**: philippedelteil - **Category**: Http - **Tags**: exposure, debug, phalcon, vuln 'yaml id: phalcon-framework-sou
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Rstudio Shiny Server prior to 1.5.16 is vulnerable to local file inclusion and source code leakage.

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-601`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Rstudio Shiny Server prior to 1.5.16 is vulnerable to local file inclusion and source code leakage. This can be exploited by appending an encoded slash to the URL. - **CVE**: CVE-2021-3374 - **Exploit Type**: Nuclei - **Exploit ID**: Nuclei-8fd6eca896449eaccb9390f9a839ccc1 - **
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: A Glossary of Blind SSRF Chains – Assetnote

- **Provenance:** Source: `CYBER_CPT/govuln` | CWE: `CWE-601`
- **Context / Surface:** Source: govuln (en)
- **Root Cause / Analysis:** ← Back to assetnote.io Request A Demo ← Back to Blog A Glossary of Blind SSRF Chains Jan 13, 2021 Introduction What is Server Side Request Forgery (SSRF)? Server Side Request Forgery occurs when you can coerce a server to make arbitrary requests on your behalf. As the requests ar
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Claude Code Leaks Data via Malicious Environment Configuration Before Trust Confirmation

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-601`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Claude Code Leaks Data via Malicious Environment Configuration Before Trust Confirmation Claude Code Leaks Data via Malicious Environment Configuration Before Trust Confirmation - **OSV ID**: GHSA-jh7p-qr78-84p7 - **CVE**: CVE-2026-21852 - **Published**: 2026-01-21T01:00:31Z -
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Claude Code Leaks Data via Malicious Environment Configuration Before Trust Confirmation

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-601`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** A vulnerability in Claude Code's project-load flow allowed malicious repositories to exfiltrate data including Anthropic API keys before users confirmed trust. If a user started Claude Code in an attacker-controller repository, and the repository included a settings file that set
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
