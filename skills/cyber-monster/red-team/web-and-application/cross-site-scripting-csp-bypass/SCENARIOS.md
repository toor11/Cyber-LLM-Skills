# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cross-site-scripting-csp-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Exploiting JSONP callback on /username/charts.json endpoint leads to information disclosure despite user'

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello! Vulnerability Details The '/username/charts.json' endpoint can return a JSONP callback due to the fact that 'jsonp_dump' is used in the file 'charts.json.spt'. It appears that the content of the JSONP request depends on the authentication of the user.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: GoAhead Web Server 5.1.1 - Digest Authentication Capture Replay Nonce Reuse

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-79`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # GoAhead Web Server 5.1.1 - Digest Authentication Capture Replay Nonce Reuse / EKU-ID: 53000 / CVE: / OSVDB-ID: / / --- / --- / --- / / Author: LiquidWorm / Published: 2020-10-27 / # Exploit Title: GoAhead Web Server 5.1.1 - Digest Authentication Capture Replay Nonce Reuse # Dat
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: GCM Nonce Reuse

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-79`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **GCM Nonce Reuse** is a catastrophic cryptographic failure where the same nonce (number used once) is used twice with the same key in AES-GCM encryption. This completely breaks both confidentiality and authentication guarantees. ### Why It's Critical AES-GCM generates a keystrea
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Sequential calls of encryption API ('encrypt', 'wrap', and 'dump') result in nonce reuse

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-79`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** **Problem**: Trying to create a new encrypted message with the same cocoon object generates the same ciphertext. It mostly affects 'MiniCocoon' and 'Cocoon' objects with custom seeds and RNGs (where 'StdRng' is used under the hood). **Note**: The issue does **NOT** affect objects
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: An exploitable nonce reuse vulnerability exists in the Web Application functionality of Moxa AWK-313

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-79`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # An exploitable nonce reuse vulnerability exists in the Web Application functionality of Moxa AWK-3131A Wireless AP running firmware 1.1. The device uses one nonce for all session authentication reques - **CVE**: CVE-2016-8712 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: In RIOT-OS 2021.01, nonce reuse in 802.15.4 encryption in the ieee820154_security component allows a

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-79`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # In RIOT-OS 2021.01, nonce reuse in 802.15.4 encryption in the ieee820154_security component allows attackers to break encryption by triggering reboots. - **CVE**: CVE-2021-41061 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-ff9dae01e70a087b6a8731a80db7a4ae - **URL**
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Assuming a database breach, nonce reuse issues in GitLab 11.6+ allows an attacker to decrypt some of

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-79`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # Assuming a database breach, nonce reuse issues in GitLab 11.6+ allows an attacker to decrypt some of the database's encrypted content - **CVE**: CVE-2021-22170 - **Exploit Type**: InTheWild - **Exploit ID**: InTheWild-1c4a49ff72dde2d1291f71ec7297395d - **URL**: https://gitlab.c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
