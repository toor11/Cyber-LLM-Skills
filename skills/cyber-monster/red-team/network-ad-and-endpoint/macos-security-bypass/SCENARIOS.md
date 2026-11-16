# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`macos-security-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Lack of quarantine meta-attribute for downloaded files leads to GateKeeper bypass

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Executable files downloaded through Brave don't have quarantine attribute. That means it's possible to launch any executable bypassing codesigning + quarantine. However, later I found that Brave has already tracked similar report but only in the context of '.pkg' files.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Gatekeeper Bypass

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Gatekeeper Bypass **ID**: T1553.001 **Type**: Technique **Tactics**: defense-impairment **Platforms**: macOS Adversaries may modify file attributes and subvert Gatekeeper functionality to evade user prompts and execute untrusted programs.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Kubernetes OPA Gatekeeper bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Kubernetes OPA Gatekeeper bypass Abusing misconfiguration Enumerate rules Having an overview may help to know which rules are active, on which mode and who can bypass it.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Hell’s Keychain: Supply-chain vulnerability in IBM Cloud Databases for PostgreSQL allows potential u

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-269`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** In this blog post we will demonstrate how we were able to leverage a privilege escalation vulnerability in PostgreSQL to uncover a long-lasting secret that could have been abused to authenticate to internal IBM Cloud CI/CD services and intervene with IBM Cloud’s internal image bu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Everyday Ghidra: Ghidra Data Types - "Keychain module analysis"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Operation triangulation - Keychain module analysis # Introduction Operation Triangulation is the name of an attack that has been targeting Kaspersky employees among others. Kaspersky has published a lot of really interesting blogposts detailing the exploit chain and how they ca
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: T1547.015 - Boot or Logon Autostart Execution: Login Items

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1547.015 - Boot or Logon Autostart Execution: Login Items ## Description from ATT&CK Adversaries may add login items to execute upon user login to gain persistence or escalate privileges. > **Jargon: Persistence** — The ability for an attacker to maintain their foothold on a c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: T1547.007 - Boot or Logon Autostart Execution: Re-opened Applications

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1547.007 - Boot or Logon Autostart Execution: Re-opened Applications ## Description from ATT&CK > **Jargon: plist (Property List)** — A standard macOS file format (often XML or binary) used to store application preferences and configuration data, acting like a settings file fo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: T1555.001 - Credentials from Password Stores: Keychain

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1555.001 - Credentials from Password Stores: Keychain > **Jargon: ATT&CK Technique ID (T1555.001)** — A standardized identifier from the MITRE ATT&CK framework, which is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
