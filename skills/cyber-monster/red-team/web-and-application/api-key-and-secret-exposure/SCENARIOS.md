# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`api-key-and-secret-exposure`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Jira Credential Disclosure within Mozilla Slack

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: I was able to find Jira Admin API Keys disclosed within Mozilla's #███ Slack channel which was posted by a staff member of Mozilla. Steps To Reproduce: 1.Navigate to the following file -█████ 2.Observe the exposed credentials on line 310-312 of the Python Script. 3.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Exposure Of Admin Username & Password

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello Team, Ther an exposure of your username and password on this subdomain https://engage2.mtnonline.com/nc/ Exposed Credentials uid: "mtnng", passwd: "bd31568138edbfc0552a1ecc6886ea5c", Steps To Reproduce: Visit https://engage2.mtnonline.com/nc/ Now, press CTRL+U to view the...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: API Key Exposure

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-798`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **API Key Exposure** occurs when API keys, tokens, or credentials are inadvertently revealed in public locations such as source code repositories, client-side code, logs, or documentation, allowing unauthorized access to APIs and services. ### Common Exposure Locations * **Git re
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Bio Basespace SDK 0.1.7 API Key Exposure

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-798`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Bio Basespace SDK 0.1.7 API Key Exposure / / / / / --- / --- / --- / / EKU-ID: 3711 / CVE: / OSVDB-ID: / / Author: Larry Cashdollar / Published: 2013-12-17 / Verified: ![Verified] (/images/accept.png) / / Download: / / / / / / --- / / Rating☆☆☆☆☆ / [![] (/images/prev.png)] (/web/3
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Nagios Log Server 2024R1.3.1 - API Key Exposure

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-798`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Nagios Log Server 2024R1.3.1 - API Key Exposure / / / / / --- / --- / --- / / EKU-ID: 56038 / CVE: / OSVDB-ID: / / Author: Seth Kraft / Published: 2025-04-11 / Verified: ![Not Verified] (/images/cancel.png) / / Download: / / / / / / --- / / Rating☆☆☆☆☆ / [![] (/images/prev.png)] (
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Pendo API Key Exposure

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-798`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Pendo API Key Exposure / - **Template ID**: pendo-api-key-exposure - **Severity**: medium - **Author**: 0x_Akoko - **Category**: File - **Tags**: file, keys, token, pendo 'yaml id: pendo-api-key-exposure info: name: Pendo API Key Exposure author: 0x_Akoko severity: medium des
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Decrypt reversible secrets encrypted using the default hardcoded key related to CVE-2020-9289 on For

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-798`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Decrypt reversible secrets encrypted using the default hardcoded key related to CVE-2020-9289 on FortiAnalyzer/FortiManager (the only difference with CVE-2019-6693 is the encryption routine). - **CVE**: CVE-2019-6693 - **Exploit Type**: GitHub - **Exploit ID**: GitHub-2785186a4
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: CSL DualCom GPRS CS2300-R devices with firmware 1.25 through 3.53 rely on a polyalphabetic substitut

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-798`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # CSL DualCom GPRS CS2300-R devices with firmware 1.25 through 3.53 rely on a polyalphabetic substitution cipher with hardcoded keys, which makes it easier for remote attackers to defeat a cryptographic - **CVE**: CVE-2015-7286 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
