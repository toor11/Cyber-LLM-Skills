# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`linux-privilege-escalation-cron-and-systemd`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: T1053.006 - Scheduled Task/Job: Systemd Timers

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1053.006 - Scheduled Task/Job: Systemd Timers > **Jargon: ATT&CK** — A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations, acting as a playbook for how hackers operate. ## Description from ATT&CK Adversaries may abuse system
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Systemd Timers

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise` | CWE: `CWE-269`
- **Context / Surface:** Source: mitre_attack_enterprise (en)
- **Root Cause / Analysis:** # Systemd Timers **ID**: T1053.006 **Type**: Technique **Tactics**: Execution, Persistence, Privilege Escalation **Platforms**: Linux Adversaries may abuse systemd timers to perform task scheduling for initial or recurring execution of malicious code. Systemd timers are unit file
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: macOS World-Writable Cron Jobs

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-269`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # macOS World-Writable Cron Jobs - **Template ID**: insecure-cron-jobs - **Severity**: medium - **Author**: geeknik - **Category**: Code - **Tags**: macos, audit, local, security, cron 'yaml id: insecure-cron-jobs info: name: macOS World-Writable Cron Jobs author: geeknik sever
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
