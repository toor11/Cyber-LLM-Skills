# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`c2-infrastructure-and-redirectors`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Domain Fronting

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Domain Fronting **ID**: T1090.004 **Type**: Technique **Tactics**: Command and Control **Platforms**: Linux, macOS, Windows, ESXi Adversaries may take advantage of routing schemes in Content Delivery Networks (CDNs) and other services which host multiple domains to obfuscate the intended...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Using CloudFront to Relay Cobalt Strike Traffic

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Using CloudFront to Relay Cobalt Strike Traffic Many of you have likely heard of Domain Fronting. Domain Fronting is a technique that can allow your C2 traffic to blend in with a target’s traffic by making it appear that it is calling out to the domain owned by your target. Thi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: How to Build a Command & Control Infrastructure with Digital Ocean: C2K Revamped

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # How to Build a Command & Control Infrastructure with Digital Ocean: C2K Revamped Expanding upon the previous post in this series, I decided to rewrite C2K to change its behavior and options for the user. In this post we will walk through the changes to C2K as well as re-deploy
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: DomCat: A Domain Categorization Tool

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # DomCat: A Domain Categorization Tool Have you ever struggled to find expired domains with the specific categorization you need? Are you frustrated by sites that list expired domains but provide no categorization data? And when you finally find a promising domain, you still have
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: How to Build a C2 Infrastructure with Digital Ocean – Part 1

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-284`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # How to Build a C2 Infrastructure with Digital Ocean – Part 1 Lee Kagan **ADVISORY: The techniques and tools referenced within this blog post may be outdated and do not apply to current situations. However, there is still potential for this blog entry to be used as an opportunit
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: VMware Host Guest Client Redirector - DLL Side Loading (Metasploit)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-284`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # VMware Host Guest Client Redirector - DLL Side Loading (Metasploit) / EKU-ID: 45908 / CVE: CVE-2016-5330 / OSVDB-ID: / / --- / --- / --- / / Author: Metasploit / Published: 2016-08-06 / Verified: Verified / [EMPTY] 'ruby require 'msf/core' class MetasploitModule < Msf::Exploi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Domain Fronting is Dead Long Live Domain Fronting

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-284`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** Domain Fronting is Dead, Long Live Domain Fronting Using TLS 1.3 to evade censors, bypass network defenses, and blend in with the noise ## 0 Domain Fronting 101 - If you wish to make an apple pie from scratch, you must first invent the universe - To understand Domain Fronting, yo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
