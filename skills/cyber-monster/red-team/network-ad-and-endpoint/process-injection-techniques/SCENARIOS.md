# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`process-injection-techniques`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Malformed .BMP file in Counter-Strike 1.6 may cause shellcode injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** With the vulnerability of the GoldSource Engine, the server is able to perform remote code execution on the client, overwriting the stack when reading the BMP file.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: macOS Thread Injection via Task port

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** macOS Thread Injection via Task port Code - https://github.com/bazad/threadexec - https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36 1. Thread Hijacking Initially, the 'task_threads()' function is invoked on the task port to obtain a thread list from the remote task.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: RDP Sessions Abuse

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** RDP Sessions Abuse RDP Process Injection If the **external group** has **RDP access** to any **computer** in the current domain, an **attacker** could **compromise that computer and wait for him**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: EDR Simulation — Hunting for Process Injection with API Monitoring

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** EDR Simulation — Hunting for Process Injection with API Monitoring Hello World, Today, We will be learning about how to use API monitoring for process injection. Let’s get started.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: [pwnable.tw] start — 100pt

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** [pwnable.tw] start — 100pt As it’s the first challenge of a wargame platform I’d expect a plain shellcode injection. That is reinforced by the binary you’re given. It read 60 bytes from stdin while it has room for only 20 bytes. You’ve executable stack.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: Module Stomping for Shellcode Injection

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-94`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Module Stomping for Shellcode Injection ## Overview Module Stomping (or Module Overloading or DLL Hollowing) is a shellcode injection (although can be used for injecting full DLLs) technique that at a high level works as follows: 1. Injects some benign Windows DLL into a remote
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: T1055.012 - Process Injection: Process Hollowing

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-94`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1055.012 - Process Injection: Process Hollowing ## Description from ATT&CK Adversaries may inject malicious code into suspended and hollowed processes in order to evade process-based defenses. > **Jargon: Process Injection** — A broad category of attacks where an attacker runs
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Process Hollowing and Portable Executable Relocations

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-94`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Process Hollowing and Portable Executable Relocations This lab is my attempt to better understand and implement a well known code injection technique called process hollowing, where a victim process is created in a suspended state, its image is carved out from memory, a malicio
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
