# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`defense-evasion-and-log-tampering-indicator-removal`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Indicator Removal from Tools

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Indicator Removal from Tools **ID**: T1027.005 **Type**: Technique **Tactics**: stealth **Platforms**: Linux, macOS, Windows Adversaries may remove indicators from tools if they believe their malicious tool was detected, quarantined, or otherwise curtailed.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: "EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543)"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-693`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** ### EntryBleed: Breaking KASLR under KPTI with Prefetch (CVE-2022-4543) Recently, I’ve discovered that Linux KPTI has implementation issues that can allow any unprivileged local attacker to bypass KASLR on Intel based systems. While technically only an info-leak, it still provide
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: T1070.006 - Indicator Removal on Host: Timestomp

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-693`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1070.006 - Indicator Removal on Host: Timestomp > **Jargon: Indicator Removal** — The act of destroying or altering evidence left behind on a computer after a cyberattack, making it harder for defenders to figure out what happened. ## Description from ATT&CK Adversaries may mo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB Sherlock: Campfire-1

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-693`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Campfire-1 is the first in a series of Sherlocks looking at identifying critical active directory vulnerabilities. This challenge requires looking at event log and prefetch data to see an attack run PowerView and the Rubeus to perform a Kerberoasting attack. ## Background ### Sce
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: HTB Sherlock: Tick Tock

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-693`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** A new employee gets a call from the “IT department”, who is actually a malicious actor. They get a TeamViewer connection and launch a Merlin C2 agent. I’ll see through the logs the processes it runs, where Defender catches it, and how it tries to mess with forensics by constantly
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB Sherlock: BFT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-693`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** BFT is all about analysis of a Master File Table (MFT). I’ll use Zimmerman tools MFTECmd and Timeline Explorer to find where a Zip archive was downloaded from Google Drive. It is then unzipped to get another zip, which is unzipped to get another zip. That final zip has a Windows
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: T1070.003 - Indicator Removal on Host: Clear Command History

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-693`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1070.003 - Indicator Removal on Host: Clear Command History > **Jargon: Indicator Removal** — The act of destroying or altering the digital evidence (indicators) left behind by an attack so that defenders and forensic analysts cannot detect the intrusion. ## Description from A
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
