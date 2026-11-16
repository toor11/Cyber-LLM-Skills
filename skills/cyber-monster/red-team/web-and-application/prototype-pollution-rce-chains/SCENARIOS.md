# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`prototype-pollution-rce-chains`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: 此漏洞为prototype pollution RCE，需要使用反弹shell或HTTP外带验证

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-1321`
- **Context / Surface:** Source: github_security_md (mixed)
- **Root Cause / Analysis:** --- id: CVE-2020-7012 title: Kibana upgrade-assistant 原型链污染RCE漏洞 (CVE-2020-7012) product: kibana vendor: Elastic version_affected: "6.7.0-6.8.8, 7.0.0-7.6.2" severity: CRITICAL tags: [rce, prototype_pollution, 需要认证] fingerprint: ["Kibana"] --- ## 漏洞描述 Kibana 6.7.0-6.8.8 和 7.0.0-7
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: This affects the package total.js before 3.4.7. The issue occurs in the image.pipe and image.stream

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-1321`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # This affects the package total.js before 3.4.7. The issue occurs in the image.pipe and image.stream functions. The type parameter is used to build the command that is then executed using child_process - **CVE**: CVE-2020-28494 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: This affects all versions of package port-killer. If (attacker-controlled) user input is given, it i

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-1321`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # This affects all versions of package port-killer. If (attacker-controlled) user input is given, it is possible for an attacker to execute arbitrary commands. This is due to use of the child_process ex - **CVE**: CVE-2021-23359 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Versions of the package network before 0.7.0 are vulnerable to Arbitrary Command Injection due to us

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-1321`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Versions of the package network before 0.7.0 are vulnerable to Arbitrary Command Injection due to use of the child_process exec function without input sanitization. If (attacker-controlled) user input - **CVE**: CVE-2024-21488 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Deno has a Command Injection via Incomplete shell metacharacter blocklist in node:child_process

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-1321`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary A command injection vulnerability exists in Deno's 'node:child_process' implementation. ## Reproduction 'javascript import { spawnSync } from "node:child_process"; import * as fs from "node:fs"; // Cleanup try { fs.unlinkSync('/tmp/rce_proof'); } catch {} // Create l
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
