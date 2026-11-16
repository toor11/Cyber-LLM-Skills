# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`xxe-oob-exfiltration`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Generic Blind XXE

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-611`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Generic Blind XXE This template detects Generic Blind XXE. - **Template ID**: generic-blind-xxe - **Severity**: high - **Author**: geeknik - **Category**: Http - **Tags**: xxe, generic, blind, vuln 'yaml id: generic-blind-xxe info: name: Generic Blind XXE author: geeknik seve
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: JAMF Blind XXE / SSRF

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-611`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # JAMF Blind XXE / SSRF Blind XXE / SSRF exists in JAMF which is a company that provides enterprise-level software solutions for managing and securing Apple devices in organizations. - **Template ID**: jamf-blind-xxe - **Severity**: medium - **Author**: pdteam - **Category**: Htt
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HuTool XML parsing module has blind XXE vulnerability

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-611`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # HuTool XML parsing module has blind XXE vulnerability HuTool XML parsing module has blind XXE vulnerability - **OSV ID**: GHSA-p2qf-9vp6-3jjq - **CVE**: CVE-2023-3276 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N - **Published**: 2023-06-15T15:30:15Z - **Modified**:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HuTool XML parsing module has blind XXE vulnerability

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-611`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** A vulnerability, which was classified as problematic, has been found in Dromara HuTool up to 5.8.19. Affected by this issue is the function readBySax of the file XmlUtil.java of the component XML Parsing Module. The manipulation leads to xml external entity reference.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Blind XXE

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-611`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **Blind XXE** is a variant of XML External Entity injection where the application does not return the entity value in its response. Attackers must use out-of-band techniques to exfiltrate data or confirm the vulnerability. ### How It Works When an XXE vulnerability exists but the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: An issue was discovered in Tufin SecureTrack 18.1 with TufinOS 2.16 build 1179(Final). The Audit Rep

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-611`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in Tufin SecureTrack 18.1 with TufinOS 2.16 build 1179(Final). The Audit Report module is affected by a blind XXE vulnerability when a new Best Practices Report is saved using - **CVE**: CVE-2018-18406 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
