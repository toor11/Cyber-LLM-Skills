# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`antivirus-evasion-and-obfuscation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Advancing Tradecraft - Context

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Donut - Injecting .NET Assemblies as Shellcode *TLDR: You can now inject .NET Assemblies into Windows processes using this repo: https://github.com/TheWover/donut/* # Advancing Tradecraft - Context Offensive and red team tradecraft have changed significantly in the past year. A
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Devnotes

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** ## 1. Introduction This document contains information useful to developers that want to integrate Donut into their own project or write their own generator in a different language. Static and dynamic examples in C are provided for Windows and Linux. There's also information about
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: GNU C Library Dynamic Loader glibc ld.so - Memory Leak / Buffer Overflow

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-693`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # GNU C Library Dynamic Loader glibc ld.so - Memory Leak / Buffer Overflow EKU-ID: 47380 / CVE: CVE-2017-1000409;CVE-2017-1000408 / OSVDB-ID: Author: Qualys Corporation / Published: 2017-12-13 Qualys Security Advisory Buffer overflow in glibc's ld.so ## Summary We have discovered
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Insecure Deserialization (pickle) in pdfminer.six CMap Loader — Local Privesc

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-693`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Overview This report demonstrates a real-world privilege escalation vulnerability in pdfminer.six due to unsafe usage of Python's 'pickle' module for CMap file loading. It shows how a low-privileged user can gain root access (or escalate to any service account) by exploiting
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Loading Windows Kernel Driver for Debugging

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Loading Windows Kernel Driver for Debugging ## Loading a Driver with OSR Driver Loader On the system where you want to load your driver (debugee), from an elevated command prompt, disable the driver integrity checks so that we can load our unsigned drivers onto Windows 10: 'c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
