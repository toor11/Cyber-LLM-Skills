# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`host-persistence-registry-and-service-persistence`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: GCP - Artifact Registry Persistence

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** GCP - Artifact Registry Persistence Artifact Registry For more information about Artifact Registry check: ../gcp-services/gcp-artifact-registry-enum.md Dependency Confusion - What happens if a **remote and a standard** repositories **are mixed in a virtual** one and a package exists in both? - The...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Registry Persistence Detection-Tryhackme Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Registry Persistence Detection - Tryhackme Writeup Learn to use the AutoRuns PowerShell module to detect persistence mechanisms that use the Registry. Link to the room https://tryhackme.com/r/room/registrypersistencedetection Task 1: Intro One crucial step that malware does upon successful execution on a target...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1547.001 - Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder ## Description from ATT&CK Adversaries may achieve persistence by adding a program to a startup folder or referencing it with a Registry run key. > **Jargon: Persistence** — A tactic where attacke
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1547.004 - Boot or Logon Autostart Execution: Winlogon Helper DLL > **Jargon: ATT&CK** — A globally-accessible knowledge base of adversary tactics and techniques based on real-world observations, used by defenders to classify and understand attacks. This technique focuses on h
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: TRY HACK ME: Registry Persistence Detection Write-Up

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TRY HACK ME: Registry Persistence Detection Write-Up ## Task 1 Introduction **Learning Objectives** - Learn how malware persists in a machine - Learn how malware uses the Registry as a persistence mechanism - Learn how to use the AutoRuns PowerShell module to detect and remedia
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Registry Persistence Detection TryHackMe Write-Up

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-269`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Registry Persistence Detection TryHackMe Write-Up ![\\"Joseph] (\\"https://miro.medium.com/v2/da:true/resize:fill:88:88/0*tvO99e3JQY70EGDi\\") ![\\"System] (\\"https://miro.medium.com/v2/resize:fill:48:48/1*gncXIKhx5QOIX0K9MGcVkg.jpeg\\") Joseph Alan · Follow Published in System
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: COM Hijacking

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # COM Hijacking > The Microsoft Component Object Model (COM) is a platform-independent, distributed, object-oriented system for creating binary software components that can interact. COM is the foundation technology for Microsoft's OLE (compound documents), ActiveX (Internet-enab
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: Bart

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Bart starts simple enough, only listening on port 80. Yet it ends up providing a path to user shell that requires enumeration of two different sites, bypassing two logins, and then finding a file upload / LFI webshell. The privesc is relateively simple, yet I ran into an interest
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
