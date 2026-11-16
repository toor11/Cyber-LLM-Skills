# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`memory-forensics-process-and-injection-analysis`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Process Hollowing and Portable Executable Relocations

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-345`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Process Hollowing and Portable Executable Relocations This lab is my attempt to better understand and implement a well known code injection technique called process hollowing, where a victim process is created in a suspended state, its image is carved out from memory, a malicio
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Module Stomping for Shellcode Injection

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-345`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Module Stomping for Shellcode Injection ## Overview Module Stomping (or Module Overloading or DLL Hollowing) is a shellcode injection (although can be used for injecting full DLLs) technique that at a high level works as follows: 1. Injects some benign Windows DLL into a remote
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: T1055.012 - Process Injection: Process Hollowing

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-345`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1055.012 - Process Injection: Process Hollowing ## Description from ATT&CK Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. > **Jargon: Process Injection** — A broad category of attacks where an attacker runs
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Module Stomping for Shellcode Injection

- **Provenance:** Source: `CYBER_CPT/ired_team` | CWE: `CWE-345`
- **Context / Surface:** Source: ired_team (en)
- **Root Cause / Analysis:** --- description: Code Injection --- # Module Stomping for Shellcode Injection ## Overview Module Stomping (or Module Overloading or DLL Hollowing) is a shellcode injection (although can be used for injecting full DLLs) technique that at a high level works as follows: 1. Injects s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Potential Process Hollowing Activity

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-345`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Potential Process Hollowing Activity Detects when a memory process image does not match the disk image, indicative of process hollowing. - **Level**: N/A - **Status**: test - **Author**: Christopher Peacock '@securepeacock', SCYTHE '@scythe_io', Sittikorn S - **Date**: 2022-01-
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
