# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`linux-privilege-escalation-kernel-and-container-escapes`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Worker container escape lead to arbitrary file reading in host machine [again]

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: After a successful build, LGTM allow user to view the file list. By default, only source code files and build config files are reserved ('lgtm.yml' and '.lgtm.yml').
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Worker container escape lead to arbitrary file reading in host machine

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Because lack of security, attacker will be able to remove original log file and replace it will a symlink to other file, After finishing job, host machine copy file from docker container.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: The Dirty Pipe Vulnerability — The Dirty Pipe Vulnerability documentation

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** Start Software Blog Team Career The Dirty Pipe Vulnerability Max Kellermann Abstract This is the story of CVE-2022-0847, a vulnerability in the Linux kernel since 5.8 which allows overwriting data in arbitrary read-only files.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Part 1

- **Provenance:** Source: `CYBER_CPT/L5/awesome_list`
- **Context / Surface:** High-depth analysis (awesome_list, edu=5)
- **Root Cause / Analysis:** CVE-2017-11176: A step-by-step Linux Kernel exploitation (part 1/4) Introduction This series covers a step-by-step walkthrough to develop a Linux kernel exploit from a CVE description.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: "Linux Kernel Exploit (CVE-2022–32250) with mqueue"

- **Provenance:** Source: `CYBER_CPT/L5/awesome_list`
- **Context / Surface:** High-depth analysis (awesome_list, edu=5)
- **Root Cause / Analysis:** Linux Kernel Exploit (CVE-2022–32250) with mqueue We exploited CVE-2022-32250, a use-after-free vulnerability in Linux Netfilter, to achieve root on Ubuntu 22.04. Learn how we bypassed KASLR and modified modprobe_path.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 6: Linux Kernel Exploitation - "Getting started & BOF"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Linux Kernel Exploitation: Getting started & BOF 03 Nov 2023 --- ## Motivation ## Where are kernel exploits used? ## Linux kernel oversimplified ## Kernelspace vs Userspace exploitation (x86_64) ### More instructions ### More registers # Motivation I started my journey into the
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Linux Kernel Exploitation - "ret2dir"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Linux Kernel PWN / 05 ret2dir 04 Feb 2023 ## 1. Introduction We have learnt some kernel PWN techniques and cases. The exploitations and mitigations bypassing are always charming, while mitigations evolve as well. In this post, we will talk about the ret2dir technique, which lev
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Linux Kernel Exploitation - "DirtyCred"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-269`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Linux Kernel PWN / 06 DirtyCred 11 Feb 2023 ## 1. Introduction Most kernel-related privilege escalation techniques are based on code execution or control flow hijacking, while some others are data-oriented attacks. The DirtyCred technique is one of such attacks, which contains
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
