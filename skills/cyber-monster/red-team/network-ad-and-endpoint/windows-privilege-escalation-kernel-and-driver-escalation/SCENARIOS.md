# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`windows-privilege-escalation-kernel-and-driver-escalation`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Base64 Beyond Encoding - Part 3

- **Provenance:** Source: `CYBER_CPT/L5/awesome_list`
- **Context / Surface:** High-depth analysis (awesome_list, edu=4)
- **Root Cause / Analysis:** Chaining N-days to Compromise All: Part 3 — Windows Driver LPE: Medium to System CVE-2023-29360, a logic bug in the mskssrv.sys driver, was exploited to escalate privileges to SYSTEM in a 1-day full chain attack.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: Linux Kernel Exploitation - "Getting started & BOF"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Linux Kernel Exploitation: Getting started & BOF 03 Nov 2023 --- ## Motivation ## Where are kernel exploits used? ## Linux kernel oversimplified ## Kernelspace vs Userspace exploitation (x86_64) ### More instructions ### More registers # Motivation I started my journey into the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Linux Kernel Exploitation - "ret2dir"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Linux Kernel PWN / 05 ret2dir 04 Feb 2023 ## 1. Introduction We have learnt some kernel PWN techniques and cases. The exploitations and mitigations bypassing are always charming, while mitigations evolve as well. In this post, we will talk about the ret2dir technique, which lev
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Linux Kernel Exploitation - "DirtyCred"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Linux Kernel PWN / 06 DirtyCred 11 Feb 2023 ## 1. Introduction Most kernel-related privilege escalation techniques are based on code execution or control flow hijacking, while some others are data-oriented attacks. The DirtyCred technique is one of such attacks, which contains
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Linux Kernel Exploitation - Part 1

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Malware Reverse Engineering for Beginners – Part 1: From 0x0 Written by Avigayil Mechtinger Already familiar with assembly language and disassemblers? Check out [Reverse Engineering for Beginners Part 2] (https://intezer.com/blog/incident-response/malware-reverse-engineering-for
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: "Linux Kernel Exploit (CVE-2022–32250) with mqueue"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Linux Kernel Exploit (CVE-2022–32250) with mqueue We exploited CVE-2022-32250, a use-after-free vulnerability in Linux Netfilter, to achieve root on Ubuntu 22.04. Learn how we bypassed KASLR and modified modprobe_path. # Linux Kernel Exploit (CVE-2022-32250) with mqueue ## Back
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: CTF Pwn - Linux Kernel Exploitation

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** For tty_struct kROP (kernel Return-Oriented Programming), userfaultfd race stabilization, SLUB internals, cross-cache attacks, and DiceCTF 2026 kernel patterns, see [kernel-techniques.md] (kernel-techniques.md). For protection bypass techniques (KASLR, FGKASLR, KPTI, SMEP, SMAP),
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
