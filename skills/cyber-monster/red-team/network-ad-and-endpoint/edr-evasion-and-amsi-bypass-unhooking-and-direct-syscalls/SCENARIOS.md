# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`edr-evasion-and-amsi-bypass-unhooking-and-direct-syscalls`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Retrieving ntdll Syscall Stubs from Disk at Run-time

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Retrieving ntdll Syscall Stubs from Disk at Run-time ## Overview The purpose of this lab was to play with syscalls once more. More specifically, the goal was to be able to retrieve ntdll syscall stubs from the disk during run-time (before AVs/EDRs get a chance to hook them), ra
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Full DLL Unhooking with C++

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Full DLL Unhooking with C++ It's possible to completely unhook any given DLL loaded in memory, by reading the .text section of ntdll.dll from disk and putting it on top of the .text section of the ntdll.dll that is mapped in memory. This may help in evading some EDR solutions t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Bypassing Cylance and other AVs/EDRs by Unhooking Windows APIs

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Bypassing Cylance and other AVs/EDRs by Unhooking Windows APIs ## Context If you've tried dumping lsass.exe process memory from an endpoint where CylancePROTECT is running, you know you will be having a hard time. This lab shows how it's still possible to dump the process memor
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Potential Direct Syscall of NtOpenProcess

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-693`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Potential Direct Syscall of NtOpenProcess Detects potential calls to NtOpenProcess directly from NTDLL. - **Level**: N/A - **Status**: test - **Author**: Christian Burkard (Nextron Systems), Tim Shelton (FP) - **Date**: 2021-07-28 - **Category**: Windows 'yaml title: Potentia
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
