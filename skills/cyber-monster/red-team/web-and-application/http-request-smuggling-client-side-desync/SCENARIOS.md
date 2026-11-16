# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`http-request-smuggling-client-side-desync`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: CVE-2022-27775: Bad local IPv6 connection reuse

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2022-27775`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: curl/libcurl doesn't consider IPv6 address zone index when doing connection reuse. if connection exists to specific IPv6 address (and other conditions for connection reuse are fulfilled) it will be reused for connections regardless of the zone index.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: TryHackMe — HTTP Browser Desync

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** TryHackMe — HTTP Browser Desync Introduction * Browser Desync is one of the latest complex web vulnerabilities that take advantage of the inconsistency in the connections between the server-side and client-sides.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: TryHackMe — HTTP Browser Desync

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-444`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe — HTTP Browser Desync # Introduction * Browser Desync is one of the latest complex web vulnerabilities that take advantage of the inconsistency in the connections between the server-side and client-sides. A successful Browser Desync exploit can expose sensitive inform
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: An authentication bypass vulnerability exists in libcurl <8.0.0 in the FTP connection reuse feature

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-444`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An authentication bypass vulnerability exists in libcurl <8.0.0 in the FTP connection reuse feature that can result in wrong credentials being used during subsequent transfers. Previously created conn - **CVE**: CVE-2023-27535 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: An authentication bypass vulnerability exists libcurl <8.0.0 in the connection reuse feature which c

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-444`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An authentication bypass vulnerability exists libcurl <8.0.0 in the connection reuse feature which can reuse previously established connections with incorrect user permissions due to a failure to chec - **CVE**: CVE-2023-27536 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
