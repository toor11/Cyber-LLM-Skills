# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`saml-assertion-attacks-assertion-forgery`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: How To Replay RF Signals Using SDR

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-347`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # How To Replay RF Signals Using SDR ## SOFTWARE DEFINED RADIO: RF Signal Replay Techniques **Disclaimer**: Be sure to use a faraday bag or cage before transmitting any data so you don’t accidentally break any laws by illegally transmitting on regulated frequencies. Additionally,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: WWBN AVideo Affected by a PayPal IPN Replay Attack Enabling Wallet Balance Inflation via Missing Tra

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-347`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The PayPal IPN v1 handler at 'plugin/PayPalYPT/ipn.php' lacks transaction deduplication, allowing an attacker to replay a single legitimate IPN notification to repeatedly inflate their wallet balance and renew subscriptions. The newer 'ipnV2.php' and 'webhook.php' hand
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: SNS FIFO Archive Replay Exfiltration via Attacker SQS FIFO Subscription

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-347`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # SNS FIFO Archive Replay Exfiltration via Attacker SQS FIFO Subscription Abuse of Amazon SNS FIFO topic message archiving to replay and exfiltrate previously published messages to an attacker-controlled SQS FIFO queue by setting the subscription ReplayPolicy. - Service: Amazon S
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: MCP Ruby SDK: Insufficient Session Binding Allows SSE Stream Hijacking via Session ID Replay

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # MCP Ruby SDK: Insufficient Session Binding Allows SSE Stream Hijacking via Session ID Replay - **OSV ID**: GHSA-qvqr-5cv7-wh35 - **CVE**: CVE-2026-33946 - **Published**: 2026-03-27T18:36:45Z - **Modified**: 2026-03-30T20:19:48.069207Z - **Affected Packages**: mcp - **Ecosystem*
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Live for Speed S1/S2/Demo - '.mpr replay' Local Buffer Overflow

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-347`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # LazyAdmin - Write-up - TryHackMe # Information ## Room - Name: LazyAdmin - Profile: tryhackme.com - Difficulty: Easy - Description: Easy linux machine to practice your skills # Write-up ## Overview Install tools used in this WU on BlackArch Linux: ' $ sudo pacman -S nmap ffuf
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Taylor has race condition in /get-patch that allows purchase token replay

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-347`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Taylor has race condition in /get-patch that allows purchase token replay - **OSV ID**: GHSA-vh5j-5fhq-9xwg - **Published**: 2025-06-27T22:06:48Z - **Modified**: 2025-06-30T12:53:28Z - **Affected Packages**: taylored - **Ecosystem**: npm I was looking at the recent fix and you
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
