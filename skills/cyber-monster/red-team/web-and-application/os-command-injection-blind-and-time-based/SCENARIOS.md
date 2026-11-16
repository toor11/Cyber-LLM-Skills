# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`os-command-injection-blind-and-time-based`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Photobomb

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Photobomb Photobomb is an easy Linux machine where plaintext credentials are used to access an internal web application with a 'Download' functionality that is vulnerable to a blind command injection.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: Cayin CMS suffers from an authenticated OS semi-blind command injection vulnerability using default

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-78`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Cayin CMS suffers from an authenticated OS semi-blind command injection vulnerability using default credentials. This can be exploited to inject and execute arbitrary shell commands as the root user t - **CVE**: CVE-2020-7357 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Tenda O3V2 v1.0.0.12(3880) was discovered to contain a Blind Command Injection via stpEn parameter i

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-78`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Tenda O3V2 v1.0.0.12(3880) was discovered to contain a Blind Command Injection via stpEn parameter in the SetStp function. This vulnerability allows attackers to execute arbitrary commands with root p - **CVE**: CVE-2024-36604 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
