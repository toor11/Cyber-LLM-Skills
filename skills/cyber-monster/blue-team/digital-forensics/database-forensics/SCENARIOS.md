# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`database-forensics`](SKILL.md) | Family: **Digital Forensics**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Bypass NTLM Message Integrity Check – Drop the MIC

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-345`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Bypass NTLM Message Integrity Check – Drop the MIC In *[An SMB Relay Race – How To Exploit LLMNR and SMB Message Signing for Fun and Profit] (https://www.blackhillsinfosec.com/an-smb-relay-race-how-to-exploit-llmnr-and-smb-message-signing-for-fun-and-profit/),* Jordan Drysdale s
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Play Integrity Attestation Bypass (SafetyNet Replacement)

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-345`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Play Integrity Attestation Bypass (SafetyNet Replacement) ## What Play Integrity Does **Play Integrity** is Google’s SafetyNet successor for **app attestation**. The app calls the API, Google Play Services gathers software/hardware signals, sends them encrypted to 'googleapis.c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Memory Integrity Enforcement: A complete vision for memory safety in Apple devices

- **Provenance:** Source: `CYBER_CPT/apple_security` | CWE: `CWE-345`
- **Context / Surface:** Source: apple_security (en)
- **Root Cause / Analysis:** Memory Integrity Enforcement (MIE) is the culmination of an unprecedented design and engineering effort, spanning half a decade, that combines the unique strengths of Apple silicon hardware with our advanced operating system security to provide industry-first, always-on memory sa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: integrity

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-345`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Complete Beginner-Network Exploitation Basics-Introductory Networking- TryHackMe ## An introduction to networking theory and basic networking tools ![\\"thomazs06\\"] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*Nt24GcB1eFI6npKLyv-3Nw.png\\") thomazs06 · Follow 14 min read
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: SandboxJS: Sandbox integrity escape

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-345`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary SandboxJS blocks direct assignment to global objects (for example 'Math.random = ...'), but this protection can be bypassed through an exposed callable constructor path: 'this.constructor.call(target, attackerObject)'. Because 'this.constructor' resolves to the intern
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: From High Integrity to SYSTEM with Name Pipes

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-345`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # From High Integrity to SYSTEM with Name Pipes **Code flow:** 1. Create a new Pipe 2. Create and start a service that will connect to the created pipe and write something. The service code will execute this encoded PS code: '$pipe = new-object System.IO.Pipes.NamedPipeClientStre
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
