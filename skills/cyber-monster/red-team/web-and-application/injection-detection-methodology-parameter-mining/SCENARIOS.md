# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`injection-detection-methodology-parameter-mining`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 api.cgi has no filtering on parameter ufconf, a

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # WAVLINK WN572HP3, WN533A8, WN530H4, WN535G3, WN531P3 api.cgi has no filtering on parameter ufconf, and this is a hidden parameter which doesn't appear in POST body, but exist in cgi binary. This leads - **CVE**: CVE-2022-35520 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
