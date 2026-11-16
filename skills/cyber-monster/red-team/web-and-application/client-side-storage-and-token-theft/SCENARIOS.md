# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`client-side-storage-and-token-theft`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: When Private Browsing mode is used, it is possible for a web worker to write persistent data to Inde

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-922`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # When Private Browsing mode is used, it is possible for a web worker to write persistent data to IndexedDB and fingerprint a user uniquely. IndexedDB should not be available in Private Browsing mode an - **CVE**: CVE-2017-7843 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Insufficient origin validation in IndexedDB in Google Chrome prior to 72.0.3626.81 allowed a remote

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-922`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Insufficient origin validation in IndexedDB in Google Chrome prior to 72.0.3626.81 allowed a remote attacker who had compromised the renderer process to bypass same origin policy via a crafted HTML pa - **CVE**: CVE-2019-5773 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Use after free in IndexedDB in Google Chrome prior to 73.0.3683.86 allowed a remote attacker who had

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-922`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Use after free in IndexedDB in Google Chrome prior to 73.0.3683.86 allowed a remote attacker who had compromised the renderer process to potentially exploit heap corruption via a crafted HTML page. - **CVE**: CVE-2019-5826 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Wire through 3.22.3993 on Windows advertises deletion of sent messages; nonetheless, all messages ca

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-922`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Wire through 3.22.3993 on Windows advertises deletion of sent messages; nonetheless, all messages can be retrieved (for a limited period of time) from the AppData\Roaming\Wire\IndexedDB\https_app.wire - **CVE**: CVE-2022-43673 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Exploiting IndexedDB API information leaks in Safari 15

- **Provenance:** Source: `CYBER_CPT/govuln` | CWE: `CWE-922`
- **Context / Surface:** Source: govuln (en)
- **Root Cause / Analysis:** Product Use Cases Resources Docs Templates Demo Pricing Login Contact Sales Get Started Back January 14, 2022 EngineeringLeak Exploiting IndexedDB API information leaks in Safari 15 Martin Bajanik Staff Engineer, Research CONTENTS A short introduction to the IndexedDB API The Ind
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
