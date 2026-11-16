# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`registry-and-file-system-forensics`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB Sherlock: Tick Tock

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** A new employee gets a call from the “IT department”, who is actually a malicious actor. They get a TeamViewer connection and launch a Merlin C2 agent. I’ll see through the logs the processes it runs, where Defender catches it, and how it tries to mess with forensics by constantly
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: Outdated

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Outdated has three steps that are all really interesting. First, I’ll exploit Folina by sending a link to an email address collected via recon over SMB. Then I’ll exploit shadow credentials to move laterally to the next user. Finally, I’ll exploit the Windows Server Update Servic
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Windows Registry Hive Exploitation Primitives

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-345`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Windows Registry Hive Exploitation Primitives ## Why hive corruption is special Windows registry hives are **memory-mapped '.regf' files** managed by a custom allocator ('HvAllocateCell', 'HvReallocateCell', 'HvFreeCell'). The allocator: - **Does not randomize allocations** – c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB Sherlock: BFT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-345`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** BFT is all about analysis of a Master File Table (MFT). I’ll use Zimmerman tools MFTECmd and Timeline Explorer to find where a Zip archive was downloaded from Google Drive. It is then unzipped to get another zip, which is unzipped to get another zip. That final zip has a Windows
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: TryHackme Expediting Registry Analysis Write-Up

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-345`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackme Expediting Registry Analysis Write-Up This Room involves acquiring live and cold system registry hives, using tools to analyze and parse the data in these hives, and addressing various questions about the system based on this analysis. ## Task 1 Introduction ### Learn
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Heads up! Xdr33, A Variant Of CIA’s HIVE Attack Kit Emerges

- **Provenance:** Source: `CYBER_CPT/netlab_360` | CWE: `CWE-345`
- **Context / Surface:** Source: netlab_360 (en)
- **Root Cause / Analysis:** # Overview On Oct 21, 2022, 360Netlab's honeypot system captured a suspicious ELF file 'ee07a74d12c0bb3594965b51d0e45b6f', which propagated via F5 vulnerability with zero VT detection, our system observces that it communicates with IP '45.9.150.144' using SSL with **forged Kasper
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
