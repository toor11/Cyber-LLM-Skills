# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-internals-and-api-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Native API

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Native API **ID**: T1106 **Type**: Technique **Tactics**: Execution **Platforms**: Linux, macOS, Windows Adversaries may interact with the native OS application programming interface (API) to execute behaviors.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Retrieving ntdll Syscall Stubs from Disk at Run-time

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Retrieving ntdll Syscall Stubs from Disk at Run-time ## Overview The purpose of this lab was to play with syscalls once more. More specifically, the goal was to be able to retrieve ntdll syscall stubs from the disk during run-time (before AVs/EDRs get a chance to hook them), ra
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Pov

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-269`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Pov offers only a web port. I'll abuse a file read and directory traversal in the web page to read the ASP.NET secrets used for VIEWSTATE, and then use ysoserial.net to make a malicious serlialized .NET payload to get execution. I'll pivot on a PowerShell credential, and then abu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: T1106 - Native API

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-269`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1106 - Native API ## Description from ATT&CK Adversaries may interact with the native OS application programming interface (API) to execute behaviors. > **Jargon: API (Application Programming Interface)** — A set of rules and tools that allows different software programs to co
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Primary Access Token Manipulation

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Primary Access Token Manipulation ## Context One of the techniques of token manipulation is creating a new process with a token "stolen" from another process. This is when a token of an already existing access token present in one of the running processes on the victim host, is
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
