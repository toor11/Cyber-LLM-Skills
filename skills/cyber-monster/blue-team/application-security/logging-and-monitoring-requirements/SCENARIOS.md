# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`logging-and-monitoring-requirements`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Rclone: Unauthenticated options/set allows runtime auth bypass, leading to sensitive operations and

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Rclone: Unauthenticated options/set allows runtime auth bypass, leading to sensitive operations and command execution - **OSV ID**: GHSA-25qr-6mpr-f7qx - **CVE**: CVE-2026-41176 - **Published**: 2026-04-22T14:44:13Z - **Modified**: 2026-04-24T09:41:43.989335069Z - **Affected Pa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: SalesLogix 6.1 does not verify if a user is authenticated before performing sensitive operations, wh

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # SalesLogix 6.1 does not verify if a user is authenticated before performing sensitive operations, which could allow remote attackers to (1) execute arbitrary SLX commands on the server or spoof the se - **CVE**: CVE-2004-1611 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Pax Technology PAXSTORE v7.0.8_20200511171508 and lower is affected by incorrect access control wher

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-778`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Pax Technology PAXSTORE v7.0.8_20200511171508 and lower is affected by incorrect access control where password revalidation in sensitive operations can be bypassed remotely by an authenticated attacke - **CVE**: CVE-2020-36125 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Synapse does not apply enough checks to servers requesting auth events of events in a room

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-778`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Synapse does not apply enough checks to servers requesting auth events of events in a room Synapse does not apply enough checks to servers requesting auth events of events in a room - **OSV ID**: GHSA-45cj-f97f-ggwv - **CVE**: CVE-2022-39335 - **CVSS**: CVSS:3.1/AV:N/AC:H/PR:L/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Synapse does not apply enough checks to servers requesting auth events of events in a room

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact Synapse is an open-source Matrix homeserver written and maintained by the Matrix.org Foundation. The Matrix Federation API allows remote homeservers to request the *authorisation events* of events in a room. This is necessary so that a homeserver receiving some events
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
