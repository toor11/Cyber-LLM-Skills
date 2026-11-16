# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`mitre-attack-mapping`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Scheduled Task

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Scheduled Task **ID**: T1053.005 **Type**: Technique **Tactics**: Execution, Persistence, Privilege Escalation **Platforms**: Windows Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Extra Window Memory Injection

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Extra Window Memory Injection **ID**: T1055.011 **Type**: Technique **Tactics**: Stealth, Privilege Escalation **Platforms**: Windows Adversaries may inject malicious code into process via Extra Window Memory (EWM) in order to evade process-based defenses as well as possibly elevate privileges.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Socket Filters

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Socket Filters **ID**: T1205.002 **Type**: Technique **Tactics**: Stealth, Persistence, Command and Control **Platforms**: Linux, macOS, Windows Adversaries may attach filters to a network socket to monitor then activate backdoors used for persistence or command and control.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: VNC

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** VNC **ID**: T1021.005 **Type**: Technique **Tactics**: Lateral Movement **Platforms**: Linux, Windows, macOS Adversaries may use Valid Accounts to remotely control machines using Virtual Network Computing (VNC).
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Archive via Utility

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Archive via Utility **ID**: T1560.001 **Type**: Technique **Tactics**: Collection **Platforms**: Linux, macOS, Windows Adversaries may use utilities to compress and/or encrypt collected data prior to exfiltration.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: Fileless Storage

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Fileless Storage **ID**: T1027.011 **Type**: Technique **Tactics**: stealth **Platforms**: Linux, Windows Adversaries may store data in "fileless" formats to conceal malicious activity from defenses. Fileless storage can be broadly defined as any format other than a file.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 7: Acquire Infrastructure

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Acquire Infrastructure **ID**: T1583 **Type**: Technique **Tactics**: resource-development **Platforms**: PRE Adversaries may buy, lease, rent, or obtain infrastructure that can be used during targeting. A wide variety of infrastructure exists for hosting and orchestrating adversary operations.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 8: Rundll32

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Rundll32 **ID**: T1218.011 **Type**: Technique **Tactics**: stealth **Platforms**: Windows Adversaries may abuse rundll32.exe to proxy execution of malicious code. Using rundll32.exe, vice executing directly (i.e.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.
