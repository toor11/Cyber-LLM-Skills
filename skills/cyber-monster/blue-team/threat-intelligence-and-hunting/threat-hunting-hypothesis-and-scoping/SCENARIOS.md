# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`threat-hunting-hypothesis-and-scoping`](SKILL.md) | Family: **Threat Intelligence and Hunting**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: The d8s-domains for python, as distributed on PyPI, included a potential code-execution backdoor ins

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # The d8s-domains for python, as distributed on PyPI, included a potential code-execution backdoor inserted by a third party. The backdoor is the democritus-hypothesis package. The affected version is 0 - **CVE**: CVE-2022-40807 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
