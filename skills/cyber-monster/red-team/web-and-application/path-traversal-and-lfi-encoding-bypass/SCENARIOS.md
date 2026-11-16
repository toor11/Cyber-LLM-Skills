# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`path-traversal-and-lfi-encoding-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: "CoRJail: From Null Byte Overflow To Docker Escape Exploiting poll_list Objects In The Linux Kernel"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-22`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # [corCTF 2022] CoRJail: From Null Byte Overflow To Docker Escape Exploiting poll_list Objects In The Linux Kernel ![[corCTF 2022] CoRJail: From Null Byte Overflow To Docker Escape Exploiting poll_list Objects In The Linux Kernel] (assets/images/title.png) CoRJail is a kernel expl
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Null Byte vs Null terminator vs Null character 😵‍💫

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-22`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Null Byte vs Null terminator vs Null character The terms "null character", "null terminator", and "null byte" all refer to the same thing: a byte with the value zero. Null character: The null character is a non-printing character that is used to represent the end of a string. I
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: WWBN AVideo has an Incomplete fix: Directory traversal bypass via query string in ReceiveImage downl

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-22`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # WWBN AVideo has an Incomplete fix: Directory traversal bypass via query string in ReceiveImage downloadURL parameters - **OSV ID**: GHSA-m63r-m9jh-3vc6 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N - **Published**: 2026-04-14T23:23:14Z - **Modified**: 2026-04-14T23:3
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Junrar has an arbitrary file write due to backslash Path Traversal bypass in LocalFolderExtractor on

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-22`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary A backslash path traversal vulnerability in 'LocalFolderExtractor' allows an attacker to write arbitrary files with attacker-controlled content anywhere on the filesystem when a crafted RAR archive is extracted on Linux/Unix. This can often lead to remote code executi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Null Byte Injection

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-22`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **Null Byte Injection** exploits how different programming languages and systems handle null bytes (0x00 or %00). In C-based systems, null bytes terminate strings, which can truncate input and bypass extension checks or filters. ### How It Works When a null byte is injected into
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Wing FTP Server Improper Neutralization of Null Byte or NUL Character Vulnerability

- **Provenance:** Source: `CYBER_CPT/cisa_kev` | CWE: `CWE-22`
- **Context / Surface:** Source: cisa_kev (en)
- **Root Cause / Analysis:** # CVE-2025-47812: Wing FTP Server Improper Neutralization of Null Byte or NUL Character Vulnerability **Vendor/Project**: Wing FTP Server **Product**: Wing FTP Server **Date Added**: 2025-07-14 **Due Date**: 2025-08-04 **Required Action**: Apply mitigations per vendor instruction
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
