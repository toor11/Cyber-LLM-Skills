# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ios-app-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Gotenberg has case-insensitive URL scheme that bypasses webhook and downloadFrom deny-list SSRF prot

- **Provenance:** Source: `CYBER_CPT/gh_security_lab` | CWE: `CWE-918`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Vulnerability Details **CWE**: CWE-918 - Server-Side Request Forgery (SSRF) The default private-IP deny-lists for --webhook-deny-list and --api-download-from-deny-list use a case-sensitive regex (^https?://). Any uppercase URL scheme variant (HTTP://, HTTPS://, Http://) bypasses the pattern.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Step 3: Web Requests

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Step 3: Web Requests HyperText Transfer Protocol (HTTP) HTTP default communication port is 80. Definitely need to remember the difference in FQDN and URL. URL Scheme — Identifies the protocol http://https:// User info — optional component with the @ after it to precede host Port — if not specified http defaults to...
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: Hell’s Keychain: Supply-chain vulnerability in IBM Cloud Databases for PostgreSQL allows potential u

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-926`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** In this blog post we will demonstrate how we were able to leverage a privilege escalation vulnerability in PostgreSQL to uncover a long-lasting secret that could have been abused to authenticate to internal IBM Cloud CI/CD services and intervene with IBM Cloud’s internal image bu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Everyday Ghidra: Ghidra Data Types - "Keychain module analysis"

- **Provenance:** Source: `CYBER_CPT/awesome_list` | CWE: `CWE-926`
- **Context / Surface:** Source: awesome_list (en)
- **Root Cause / Analysis:** # Operation triangulation - Keychain module analysis # Introduction Operation Triangulation is the name of an attack that has been targeting Kaspersky employees among others. Kaspersky has published a lot of really interesting blogposts detailing the exploit chain and how they ca
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: macOS Dangerous Entitlements & TCC perms

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-926`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # macOS Dangerous Entitlements & TCC perms > Note that entitlements starting with **'com.apple'** are not available to third-parties, only Apple can grant them... Or if you are using an enterprise certificate you could create your own entitlements starting with **'com.apple'** ac
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Mach-O Entitlements Extraction & IPSW Indexing

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-926`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Mach-O Entitlements Extraction & IPSW Indexing ## Overview This page covers how to extract entitlements from Mach-O binaries programmatically by walking LC_CODE_SIGNATURE and parsing the code signing SuperBlob, and how to scale this across Apple IPSW firmwares by mounting and i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: How to load unsigned or fake-signed apps on iOS

- **Provenance:** Source: `CYBER_CPT/pentest_partners` | CWE: `CWE-926`
- **Context / Surface:** Source: pentest_partners (en)
- **Root Cause / Analysis:** ### TL;DR * Issues commonly arise when clients provide an application which is unsigned or does not meet device requirements. * Installing an application can be challenging without a Mac, access to Xcode or if the client is having trouble signing the application manually as this
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: T1555.001 - Credentials from Password Stores: Keychain

- **Provenance:** Source: `CYBER_CPT/atomic_red_team` | CWE: `CWE-926`
- **Context / Surface:** Source: atomic_red_team (en)
- **Root Cause / Analysis:** # T1555.001 - Credentials from Password Stores: Keychain > **Jargon: ATT&CK Technique ID (T1555.001)** — A standardized identifier from the MITRE ATT&CK framework, which is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
