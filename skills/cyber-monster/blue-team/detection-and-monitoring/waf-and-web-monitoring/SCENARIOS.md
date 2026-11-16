# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`waf-and-web-monitoring`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Fickling vulnerable to use of ctypes and pydoc gadget chain to bypass detection

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Fickling's assessment 'pydoc' and 'ctypes' were added to the list of unsafe imports (https://github.com/trailofbits/fickling/commit/b793563e60a5e039c5837b09d7f4f6b92e6040d1). # Original report ### Summary Both ctypes and pydoc modules arent explictly blocked. Even other existin
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: AI Safety Control Bypass Detection

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-778`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # AI Safety Control Bypass Detection - **Template ID**: ai-safety-bypass - **Severity**: unknown - **Author**: princechaddha - **Category**: Dast - **Tags**: ai, dast 'yaml id: ai-safety-bypass info: name: AI Safety Control Bypass Detection author: princechaddha severity: unkno
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: WordPress Wordfence - WAF Logs and Data Disclosure

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-778`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # WordPress Wordfence - WAF Logs and Data Disclosure / - **Template ID**: wordfence-waf-logs-disclosure - **Severity**: low - **Author**: ritikchaddha - **Category**: Http - **Tags**: wordpress, wp, wp-plugin, wordfence, logs, exposure 'yaml id: wordfence-waf-logs-disclosure in
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Fickling vulnerable to use of ctypes and pydoc gadget chain to bypass detection

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Fickling vulnerable to use of ctypes and pydoc gadget chain to bypass detection Fickling vulnerable to use of ctypes and pydoc gadget chain to bypass detection - **OSV ID**: GHSA-5hvc-6wx8-mvv4 - **CVE**: CVE-2026-22608 - **Published**: 2026-01-09T21:05:13Z - **Modified**: 2026
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: An NC-25986 issue was discovered in the Logging subsystem of Sophos XG Firewall with SFOS before 17.

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An NC-25986 issue was discovered in the Logging subsystem of Sophos XG Firewall with SFOS before 17.0.3 MR3. An unauthenticated user can trigger a persistent XSS vulnerability found in the WAF log pag - **CVE**: CVE-2017-18014 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: An issue was discovered in armadito-windows-driver/src/communication.c in Armadito 0.12.7.2. Malware

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An issue was discovered in armadito-windows-driver/src/communication.c in Armadito 0.12.7.2. Malware with filenames containing pure UTF-16 characters can bypass detection. The user-mode service will f - **CVE**: CVE-2018-7289 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
