# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`byovd-and-driver-abuse`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Cracking Windows Kernel with HEVD - "Chapter 0"

- **Provenance:** Source: `CYBER_CPT/L5/awesome_list`
- **Context / Surface:** High-depth analysis (awesome_list, edu=4)
- **Root Cause / Analysis:** [Cracking Windows Kernel with HEVD] Chapter 0: Where do I start? Cracking HackSys Extreme Vulnerable Driver: where do I start? What is this? Hello! Previously we exploited vulnerable linux driver by invictus-0x90.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 2: HTB: Reaper

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-781`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Reaper starts with a simple key validation service. I’ll find the binary on an open FTP and reverse it to find both a buffer overflow and a format string vulnerability. I’ll abuse the format string to leak a memory address to bypass ASLR. Then I’ll abuse the overflow with ROP to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Sending Commands from your Userland Program to your Kernel Driver via IOCTL

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-781`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Sending Commands from your Userland Program to your Kernel Driver via IOCTL This is a quick lab that demonstrates how to: * create a simple WDM kernel mode driver that can receive and respond to a custom defined input/output control code (IOCTL) that sent in from the userland p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Subscribing to Process Creation, Thread Creation and Image Load Notifications from a Kernel Driver

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-781`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Subscribing to Process Creation, Thread Creation and Image Load Notifications from a Kernel Driver This is a quick lab to play with some of the interesting notifications that kernel drivers can subscribe to: * 'PsSetCreateProcessNotifyRoutine' - notifies the driver about new/te
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: AF_UNIX MSG_OOB UAF & SKB-based kernel primitives

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-781`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # AF_UNIX MSG_OOB UAF & SKB-based kernel primitives ## TL;DR - Linux >=6.9 introduced a flawed 'manage_oob()' refactor ('5aa57d9f2d53') for AF_UNIX 'MSG_OOB' handling. Stacked zero-length SKBs bypassed the logic that clears 'u->oob_skb', so a normal 'recv()' could free the out-of
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Windows 2k3 SP2 TCP/IP IOCTL Privilege Escalation (MS14-070)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-781`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Microsoft Windows Server 2003 SP2 - TCP/IP IOCTL Privilege Escalation (MS14-070) EKU-ID: 42186 CVE: CVE-2014-4076;OSVDB-114532;MS14-070 Author: Tomislav Paskalev Published: 2015-08-12 'c /* ################################################################ # Exploit Title: Wind
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Agenda Ransomware Deploys Linux Variant on Windows Systems Through Remote Management Tools and BYOVD

- **Provenance:** Source: `CYBER_CPT/trend_micro_research` | CWE: `CWE-781`
- **Context / Surface:** Source: trend_micro_research (en)
- **Root Cause / Analysis:** Ransomware # Agenda Ransomware Deploys Linux Variant on Windows Systems Through Remote Management Tools and BYOVD Techniques Trend™ Research identified a sophisticated Agenda ransomware attack that deployed a Linux variant on Windows systems. This cross-platform execution can mak
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
