# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ios-app-security-binary-and-entitlements`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: macOS Dangerous Entitlements & TCC perms

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-926`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # macOS Dangerous Entitlements & TCC perms > Note that entitlements starting with **'com.apple'** are not available to third-parties, only Apple can grant them... Or if you are using an enterprise certificate you could create your own entitlements starting with **'com.apple'** ac
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Mach-O Entitlements Extraction & IPSW Indexing

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-926`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Mach-O Entitlements Extraction & IPSW Indexing ## Overview This page covers how to extract entitlements from Mach-O binaries programmatically by walking LC_CODE_SIGNATURE and parsing the code signing SuperBlob, and how to scale this across Apple IPSW firmwares by mounting and i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Extracting Entitlements from Compiled Application

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-926`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Extracting Entitlements from Compiled Application ### **Extracting Entitlements and Mobile Provision Files** When dealing with an app's IPA or an installed app on a jailbroken device, finding '.entitlements' files or the 'embedded.mobileprovision' file directly may not be possi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Apple Mac OSX Entitlements - 'Rootpipe' Local Privilege Escalation (Metasploit)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-926`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Apple Mac OSX Entitlements - 'Rootpipe' Local Privilege Escalation (Metasploit) / EKU-ID: 42458 / CVE: CVE-2015-3673;OSVDB-123922 / OSVDB-ID: / / --- / --- / --- / / Author: Metasploit / Published: 2015-08-31 / Verified: Verified / 'ruby ## # This module requires Metasploit:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Command Injection in entitlements

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-926`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Command Injection in entitlements Command Injection in entitlements - **OSV ID**: GHSA-g8vp-6hv4-m67c - **Published**: 2020-09-11T21:23:29Z - **Modified**: 2020-08-31T18:43:32Z - **Affected Packages**: entitlements - **Ecosystem**: npm Versions of 'entitlements' prior to 1.3.0
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
