# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`network-forensics-and-pcap-protocol-reconstruction`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: opentelemetry-go: OTLP HTTP exporters read unbounded HTTP response bodies

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-345`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # opentelemetry-go: OTLP HTTP exporters read unbounded HTTP response bodies opentelemetry-go: OTLP HTTP exporters read unbounded HTTP response bodies - **OSV ID**: GHSA-w8rr-5gcm-pp58 - **CVE**: CVE-2026-39882 - **CVSS**: CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H - **Published
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: opentelemetry-go: OTLP HTTP exporters read unbounded HTTP response bodies

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-345`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** overview: this report shows that the otlp HTTP exporters (traces/metrics/logs) read the full HTTP response body into an in-memory 'bytes.Buffer' without a size cap. this is exploitable for memory exhaustion when the configured collector endpoint is attacker-controlled (or a netwo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Integer overflow in the TCP stream reassembly module (stream4) for Snort 2.0 and earlier allows remo

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-345`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Integer overflow in the TCP stream reassembly module (stream4) for Snort 2.0 and earlier allows remote attackers to execute arbitrary code via large sequence numbers in packets, which enable a heap-ba - **CVE**: CVE-2003-0209 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: D-Link routers with the mydlink feature have some web interfaces without authentication requirements

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-345`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # D-Link routers with the mydlink feature have some web interfaces without authentication requirements. An attacker can remotely obtain users' DNS query logs and login logs. Vulnerable targets include b - **CVE**: CVE-2019-7642 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
