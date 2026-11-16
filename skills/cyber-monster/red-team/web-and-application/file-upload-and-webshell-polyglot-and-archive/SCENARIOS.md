# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`file-upload-and-webshell-polyglot-and-archive`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: MONAI has Path Traversal (Zip Slip) in NGC Private Bundle Download

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-434`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # MONAI has Path Traversal (Zip Slip) in NGC Private Bundle Download - **OSV ID**: GHSA-9rg3-9pvr-6p27 - **CVE**: CVE-2026-21851 - **CVSS**: CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:N - **Published**: 2026-01-06T17:32:52Z - **Modified**: 2026-02-03T03:03:55.088350Z - **Affected
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: SiYuan vulnerable to RCE via zip slip and Command Injection via PandocBin

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-434`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # SiYuan vulnerable to RCE via zip slip and Command Injection via PandocBin - **OSV ID**: GHSA-4r66-7rcv-x46x - **Published**: 2025-12-09T17:18:16Z - **Modified**: 2025-12-15T20:41:18.297560Z - **Affected Packages**: github.com/siyuan-note/siyuan/kernel - **Ecosystem**: Go ### Su
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: ApostropheCMS has Arbitrary File Write (Zip Slip / Path Traversal) in Import-Export Gzip Extraction

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-434`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** **Reported:** 2026-03-08 **Status:** patched and released in version 3.5.3 of '@apostrophecms/import-export' --- ## Product / Field / Value / /---/---/ / Repository / 'apostrophecms/apostrophe' (monorepo) / / Affected Package / '@apostrophecms/import-export' / / Affected File / '
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: SiYuan vulnerable to RCE via zip slip and Command Injection via PandocBin

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-434`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary Siyuan is vulnerable to RCE. The issue stems from a "Zip Slip" vulnerability during zip file extraction, combined with the ability to overwrite system executables and subsequently trigger their execution. ### Steps to reproduce 1. Authenticate 2. Create zip slip paylo
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Code Extension Marketplace: Zip Slip Path Traversal

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-434`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Zip Slip Path Traversal in coder/code-marketplace ## Summary A Zip Slip (CWE-22) vulnerability in 'coder/code-marketplace' ≤ v2.4.1 allowed a malicious VSIX file to write arbitrary files outside the extension directory. 'ExtractZip' passed raw zip entry names to a callback that
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: PraisonAI Has Arbitrary File Write (Zip Slip) in Templates Extraction

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-434`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # PraisonAI Has Arbitrary File Write (Zip Slip) in Templates Extraction - **OSV ID**: GHSA-4ph2-f6pf-79wv - **CVE**: CVE-2026-39307 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H - **Published**: 2026-04-06T23:08:55Z - **Modified**: 2026-04-07T22:21:26.232324Z - **Affec
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
