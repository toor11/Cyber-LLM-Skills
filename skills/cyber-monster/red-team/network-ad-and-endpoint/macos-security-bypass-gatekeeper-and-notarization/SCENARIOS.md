# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`macos-security-bypass-gatekeeper-and-notarization`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Keybase client: downloaded executables lack "com.apple.quarantine" meta-attribute [macOS]

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary 1. Missing quarantine attribute for downloaded files allows remote attacker to send executable file that won't be checked by Gatekeeper (codesign bypass). 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Lack of quarantine meta-attribute for downloaded files leads to GateKeeper bypass

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Executable files downloaded through Brave don't have quarantine attribute. That means it's possible to launch any executable bypassing codesigning + quarantine. However, later I found that Brave has already tracked similar report but only in the context of '.pkg' files.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Kubernetes OPA Gatekeeper bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Kubernetes OPA Gatekeeper bypass Abusing misconfiguration Enumerate rules Having an overview may help to know which rules are active, on which mode and who can bypass it.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: HTB: Shrek

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Shrek is another 2018 HackTheBox machine that is more a string of challenges as opposed to a box. I’ll find an uploads page in the website that doesn’t work, but then also find a bunch of malware (or malware-ish) files in the uploads directory. One of them contains a comment abou
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: T1218 - Signed Binary Proxy Execution

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1218 - Signed Binary Proxy Execution ## Description from ATT&CK > Adversaries may bypass process and/or signature-based defenses by proxying execution of malicious content with signed, or otherwise trusted, binaries. > **Jargon: Signed Binary Proxy Execution** — Using a legiti
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: T1218.001 - Signed Binary Proxy Execution: Compiled HTML File

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1218.001 - Signed Binary Proxy Execution: Compiled HTML File ## Description from ATT&CK > Adversaries may abuse Compiled HTML files (.chm) to conceal malicious code. CHM files are commonly distributed as part of the Microsoft HTML Help system. CHM files are compressed compilat
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: T1218.004 - Signed Binary Proxy Execution: InstallUtil

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1218.004 - Signed Binary Proxy Execution: InstallUtil ## Description from ATT&CK > Adversaries may use InstallUtil to proxy execution of code through a trusted Windows utility. > **Jargon: Proxy Execution** — Running malicious code by hiding it behind a legitimate, trusted pro
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: T1218.007 - Signed Binary Proxy Execution: Msiexec

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1218.007 - Signed Binary Proxy Execution: Msiexec ## Description from ATT&CK > Adversaries may abuse msiexec.exe to proxy execution of malicious payloads. Msiexec.exe is the command-line utility for the Windows Installer and is thus commonly associated with executing installat
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
