# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`process-injection-techniques-classic-and-apc-injection`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: macOS Thread Injection via Task port

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** macOS Thread Injection via Task port Code - https://github.com/bazad/threadexec - https://gist.github.com/knightsc/bd6dfeccb02b77eb6409db5601dcef36 1. Thread Hijacking Initially, the 'task_threads()' function is invoked on the task port to obtain a thread list from the remote task.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Injecting to Remote Process via Thread Hijacking

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-94`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Injecting to Remote Process via Thread Hijacking This is a quick lab that looks at the API sequence used by malware to inject into remote processes by leveraging a well known thread hijacking technique. ## Overview Below lists the API calls that are required to execute this tec
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: NtCreateSection + NtMapViewOfSection Code Injection

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-94`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # NtCreateSection + NtMapViewOfSection Code Injection ## Overview This lab is for a code injection technique that leverages Native APIs 'NtCreateSection', 'NtMapViewOfSection' and 'RtlCreateUserThread'. * Section is a memory block that is shared between processes and can be creat
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
