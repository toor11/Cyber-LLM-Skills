# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`denial-of-service-response`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Analyzing 85 GB of PCAP in 2 hours

- **Provenance:** Source: `CYBER_CPT/netresec`
- **Context / Surface:** PCAP / Network Forensics (en)
- **Root Cause / Analysis:** Analyzing 85 GB of PCAP in 2 hours Lets say you've collected around 100 GB of PCAP files in a network monitoring installation. How would you approach the task of looking at the application layer data of a few of the captured sessions or flows? For much smaller datasets, in the order of 100 MB, one...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Mail Protocols

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Mail Protocols **ID**: T1071.003 **Type**: Technique **Tactics**: Command and Control **Platforms**: Linux, macOS, Network Devices, Windows Adversaries may communicate using application layer protocols associated with electronic mail delivery to avoid detection/network filtering by blending in with...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: T1095 - Non-Application Layer Protocol

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-778`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1095 - Non-Application Layer Protocol ## Description from ATT&CK Adversaries may use an OSI non-application layer protocol for communication between host and C2 server or among infected hosts within a network. > **Jargon: C2 (Command and Control)** — A channel used by attacker
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Reminders – Simple Security and Finding Sanity In the Digital Age

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-778`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** 1. **Analyze the Request:** * **Role:** Master cybersecurity educator. * **Target Audience:** Bright but novice security learner. * **Goal:** Deeply elucidate, make complex intuitive, make implicit explicit. * **UNBREAKABLE RULES:** * (a) Technical Correctness: Preserve all detai
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: T1071.004 - Application Layer Protocol: DNS

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-778`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1071.004 - Application Layer Protocol: DNS ## Description from ATT&CK > Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: T1071.001 - Application Layer Protocol: Web Protocols

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-778`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1071.001 - Application Layer Protocol: Web Protocols > **Jargon: Application Layer Protocol** — The rules that allow software applications to communicate over a network, like HTTP for web browsing or SMTP for email. ## Description from ATT&CK > Adversaries may communicate usin
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: WWBN AVideo's GIF poster fetch bypasses traversal scrubbing and exposes local files through public m

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-778`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary 'objects/aVideoEncoderReceiveImage.json.php' allowed an authenticated uploader to fetch attacker-controlled same-origin '/videos/...' URLs, bypass traversal scrubbing, and expose server-local files through the GIF poster storage path. The vulnerable GIF branch could be
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: T1071 - Application Layer Protocol

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-778`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1071 - Application Layer Protocol ## Description from ATT&CK > Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic. Commands to the remote system, and often the results of those commands, w
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
