# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`xml-attacks-xxe-and-xslt-xslt-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: XSLT Injection

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-611`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **XSLT Injection** is a vulnerability where attackers can inject malicious content into XSLT (Extensible Stylesheet Language Transformations) stylesheets, potentially leading to information disclosure, server-side request forgery, or remote code execution. ### How It Works XSLT t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: An issue was discovered in OverIT Geocall before 8.0. An authenticated user who has the Test Trasfor

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-611`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in OverIT Geocall before 8.0. An authenticated user who has the Test Trasformazione XSL functionality enabled can exploit a XSLT Injection vulnerability. Attackers could exploi - **CVE**: CVE-2022-22834 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: veraPDF has potential XSLT injection vulnerability when using policy files

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-611`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # veraPDF has potential XSLT injection vulnerability when using policy files veraPDF has potential XSLT injection vulnerability when using policy files - **OSV ID**: GHSA-qxqf-2mfx-x8jw - **CVE**: CVE-2024-28109 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N - **Publish
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Apache Wicket: Remote code execution via XSLT injection

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-611`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** The default configuration of XSLTResourceStream.java is vulnerable to remote code execution via XSLT injection when processing input from an untrusted source without validation. Users are recommended to upgrade to versions 10.1.0, 9.18.0 or 8.16.0, which fix this issue.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: veraPDF has potential XSLT injection vulnerability when using policy files

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-611`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact Executing policy checks using custom schematron files invokes an XSL transformation that may theoretically lead to a remote code execution (RCE) vulnerability. ### Patches This has been patched and users should upgrade to veraPDF v1.24.2 ### Workarounds This doesn't af
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
