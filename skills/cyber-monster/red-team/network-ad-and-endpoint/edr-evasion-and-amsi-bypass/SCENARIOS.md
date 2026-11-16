# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`edr-evasion-and-amsi-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Bypassing Cylance: Part 4 – Metasploit Meterpreter & PowerShell Empire Agent

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-693`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** 1. **Analyze the Request:** * **Role:** Master cybersecurity educator. * **Target Audience:** Bright but novice security learner. * **Goal:** Deeply elucidate, making complex intuitive and implicit explicit. * **Unbreakable Rules:** * (a) Technical Correctness: Preserve all detai
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Power Posing with PowerOPS

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-693`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** 1. **Analyze the Request:** * **Role:** Master cybersecurity educator. * **Goal:** Transform dense, expert-level text into clear, educational material for a bright novice. Elucidate deeply, making complex intuitive and implicit explicit. * **UNBREAKABLE RULES:** * (a) Technical C
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Full DLL Unhooking with C++

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Full DLL Unhooking with C++ It's possible to completely unhook any given DLL loaded in memory, by reading the .text section of ntdll.dll from disk and putting it on top of the .text section of the ntdll.dll that is mapped in memory. This may help in evading some EDR solutions t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Windows - AMSI Bypass

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Windows - AMSI Bypass ## List AMSI Providers * List providers with : 'Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\' * Find software from CLSID 'ps1 Get-ChildItem -Path 'HKLM:\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}' Name Property ---- -
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Bypassing Cylance and other AVs/EDRs by Unhooking Windows APIs

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Bypassing Cylance and other AVs/EDRs by Unhooking Windows APIs ## Context If you've tried dumping lsass.exe process memory from an endpoint where CylancePROTECT is running, you know you will be having a hard time. This lab shows how it's still possible to dump the process memor
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
