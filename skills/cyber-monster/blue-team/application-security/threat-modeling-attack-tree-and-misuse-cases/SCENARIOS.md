# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`threat-modeling-attack-tree-and-misuse-cases`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: PeteReport Version 0.5 allows an authenticated admin user to inject persistent JavaScript code while

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-20`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # PeteReport Version 0.5 allows an authenticated admin user to inject persistent JavaScript code while adding an 'Attack Tree' by modifying the 'svg_file' parameter. - **CVE**: CVE-2022-23051 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-d19c3952ada7d91e6dd8ea67ff06f3
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
