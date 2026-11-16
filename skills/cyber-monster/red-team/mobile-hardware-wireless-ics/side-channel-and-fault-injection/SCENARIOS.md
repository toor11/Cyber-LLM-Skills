# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`side-channel-and-fault-injection`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: OpenSSL vulnerable to the Marvin Attack (CVE-2022-4304)

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2022-4304`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** A timing based side channel exists in the OpenSSL RSA Decryption implementation which could be sufficient to recover a plaintext across a network in a Bleichenbacher style attack.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Event Loop Blocking + Lazy images

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Event Loop Blocking + Lazy images In **this exploit**, **@aszx87410** mixes the **lazy image side channel** technique through a HTML injection with kind of **event loop blocking technique** to leak chars.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: XS-Search/XS-Leaks

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** XS-Search/XS-Leaks {{#include ../banners/hacktricks-training.md}} Basic Information XS-Search is a method used for **extracting cross-origin information** by leveraging **side channel vulnerabilities**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Fault Injection Attacks

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Fault Injection Attacks {{#include ../../banners/hacktricks-training.md}} Fault injections attacks includes introducing external distrubance in electronic circuits to influence it's behaviour, resulting to disclose information or even bypass certian restrictions in the circuit.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 5: Side Channel Analysis Attacks

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Side Channel Analysis Attacks Side-channel attacks recover secrets by observing physical or micro-architectural "leakage" that is *correlated* with internal state but is *not* part of the logical interface of the device.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: Bypassing debug password protection on the RH850 family using fault injection

- **Provenance:** Source: `CYBER_CPT/quarkslab` | CWE: `CWE-1300`
- **Context / Surface:** Source: quarkslab (en)
- **Root Cause / Analysis:** ## Introduction The RH850 family is a range of high-performance and high-reliability 32-bit microcontrollers for Renesas, dedicated to the automotive industry. These microcontrollers are the most common ones we have to work with in the various Electronic Control Units (ECU) we au
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: [TryHackMe] GLITCH — Official Writeup

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-1300`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # [TryHackMe] GLITCH — Official Writeup # Introduction This is the official writeup for the GLITCH room on TryHackMe, it is the first challenge I created and also my first writeup, feedback is appreciated. You can always DM me on Twitter at @infamous551. The box showcases a simpl
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Glitch Write-Up

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-1300`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Glitch Write-Up ## Description Glitch is a room on TryHackMe. It has “Easy” difficulty. Initial foothold on the machine could be obtained by a remote code execution flaw in the API. Privilege escalation to root could be accomplished by reused credentials that were stored inside
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
