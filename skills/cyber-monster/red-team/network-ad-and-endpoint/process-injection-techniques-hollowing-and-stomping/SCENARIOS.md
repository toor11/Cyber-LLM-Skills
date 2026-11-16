# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`process-injection-techniques-hollowing-and-stomping`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Module Stomping for Shellcode Injection

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-94`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Module Stomping for Shellcode Injection ## Overview Module Stomping (or Module Overloading or DLL Hollowing) is a shellcode injection (although can be used for injecting full DLLs) technique that at a high level works as follows: 1. Injects some benign Windows DLL into a remote
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Process Hollowing and Portable Executable Relocations

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-94`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Process Hollowing and Portable Executable Relocations This lab is my attempt to better understand and implement a well known code injection technique called process hollowing, where a victim process is created in a suspended state, its image is carved out from memory, a malicio
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Process Doppelganging

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-94`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Process Doppelganging This lab is simply a run of the tool written by @hasherezade that was inspired by the BlackHat talk by Tal Liberman and Eugene Kogan where they presented their research on Process Doppelganging. Process doppelganging is a code injection technique that leve
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: T1055.012 - Process Injection: Process Hollowing

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-94`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1055.012 - Process Injection: Process Hollowing ## Description from ATT&CK Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. > **Jargon: Process Injection** — A broad category of attacks where an attacker runs
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Module Stomping for Shellcode Injection

- **Provenance:** Source: `CYBER_CPT/ired_team` | CWE: `CWE-94`
- **Context / Surface:** Source: ired_team (en)
- **Root Cause / Analysis:** --- description: Code Injection --- # Module Stomping for Shellcode Injection ## Overview Module Stomping (or Module Overloading or DLL Hollowing) is a shellcode injection (although can be used for injecting full DLLs) technique that at a high level works as follows: 1. Injects s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
