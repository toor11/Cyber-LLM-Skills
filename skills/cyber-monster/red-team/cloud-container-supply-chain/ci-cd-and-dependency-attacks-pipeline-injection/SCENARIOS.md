# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ci-cd-and-dependency-attacks-pipeline-injection`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: n8n < 1.120.4, 1.121.1, 1.122.0 contains a remote code execution caused by insufficient isolation in

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-1357`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # n8n < 1.120.4, 1.121.1, 1.122.0 contains a remote code execution caused by insufficient isolation in workflow expression evaluation, letting authenticated attackers execute arbitrary code with n8n pro - **CVE**: CVE-2025-68613 - **Exploit Type**: Nuclei - **Exploit ID**: Nuclei
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: n8n Unsafe Workflow Expression Evaluation Allows Remote Code Execution

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-1357`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # n8n Unsafe Workflow Expression Evaluation Allows Remote Code Execution n8n Unsafe Workflow Expression Evaluation Allows Remote Code Execution - **OSV ID**: GHSA-5xrp-6693-jjx9 - **CVE**: CVE-2026-1470 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H - **Published**: 202
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: n8n Unsafe Workflow Expression Evaluation Allows Remote Code Execution

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1357`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** n8n contains a critical Remote Code Execution (RCE) vulnerability in its workflow Expression evaluation system. Expressions supplied by authenticated users during workflow configuration may be evaluated in an execution context that is not sufficiently isolated from the underlying
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
