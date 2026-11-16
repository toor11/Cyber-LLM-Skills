# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`defense-evasion-and-log-tampering`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Indicator Removal from Tools

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Indicator Removal from Tools **ID**: T1027.005 **Type**: Technique **Tactics**: stealth **Platforms**: Linux, macOS, Windows Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: T1070.006 - Indicator Removal on Host: Timestomp

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-693`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1070.006 - Indicator Removal on Host: Timestomp > **Jargon: Indicator Removal** — The act of destroying or altering evidence left behind on a computer after a cyberattack, making it harder for defenders to figure out what happened. ## Description from ATT&CK Adversaries may mo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: T1070.003 - Indicator Removal on Host: Clear Command History

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-693`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1070.003 - Indicator Removal on Host: Clear Command History > **Jargon: Indicator Removal** — The act of destroying or altering the digital evidence (indicators) left behind by an attack so that defenders and forensic analysts cannot detect the intrusion. ## Description from A
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: T1070.004 - Indicator Removal on Host: File Deletion

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-693`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1070.004 - Indicator Removal on Host: File Deletion Think of this technique as a digital burglar wiping their fingerprints off the doorknob before leaving the scene of a crime. In cybersecurity, when attackers break into a system, they often bring tools or create files. If the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-693`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Potential Defense Evasion Activity Via Emoji Usage In CommandLine - 2 Detects the usage of emojis in the command line, this could be a sign of potential defense evasion activity. - **Level**: N/A - **Status**: test - **Author**: @Kostastsale, TheDFIRReport - **Date**: 2022-12-0
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Audit Policy Tampering Via Auditpol

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-693`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Audit Policy Tampering Via Auditpol - **Level**: N/A - **Status**: test - **Author**: Janantha Marasinghe (https://github.com/blueteam0ps) - **Date**: 2021-02-02 - **Category**: Windows ## Rule 'yaml title: Audit Policy Tampering Via Auditpol id: 0a13e132-651d-11eb-ae93-0242a
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Audit Policy Tampering Via NT Resource Kit Auditpol

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-693`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Audit Policy Tampering Via NT Resource Kit Auditpol - **Level**: N/A - **Status**: test - **Author**: Nasreddine Bencherchali (Nextron Systems) - **Date**: 2021-12-18 - **Category**: Windows ## Rule 'yaml title: Audit Policy Tampering Via NT Resource Kit Auditpol id: c6c56ada
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
