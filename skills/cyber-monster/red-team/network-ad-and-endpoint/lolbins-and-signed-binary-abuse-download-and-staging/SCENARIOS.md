# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`lolbins-and-signed-binary-abuse-download-and-staging`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Bitsadmin

- **Provenance:** Source: `CYBER_CPT/lolbas` | CWE: `CWE-284`
- **Context / Surface:** Source: lolbas (en)
- **Root Cause / Analysis:** # [..] (/) /Bitsadmin.exe [Star] (https://github.com/LOLBAS-Project/LOLBAS) [Alternate data streams] (/lolbas/Binaries/Bitsadmin/#ads) [Download] (/lolbas/Binaries/Bitsadmin/#download) [Copy] (/lolbas/Binaries/Bitsadmin/#copy) [Execute] (/lolbas/Binaries/Bitsadmin/#execute) Used for ma
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: New BITS Job Created Via Bitsadmin

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-284`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # New BITS Job Created Via Bitsadmin Detects the creation of a new bits job by Bitsadmin - **Level**: N/A - **Status**: test - **Author**: frack113 - **Date**: 2022-03-01 - **Category**: Windows ## Rule 'yaml title: New BITS Job Created Via Bitsadmin id: 1ff315dc-2a3a-4b71-8dde
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Suspicious Download From Direct IP Via Bitsadmin

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-284`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Suspicious Download From Direct IP Via Bitsadmin Detects usage of bitsadmin downloading a file using an URL that contains an IP - **Level**: N/A - **Status**: test - **Author**: Florian Roth (Nextron Systems) - **Date**: 2022-06-28 - **Category**: Windows ## Rule 'yaml title:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: File Download Via Bitsadmin To A Suspicious Target Folder

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-284`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # File Download Via Bitsadmin To A Suspicious Target Folder Detects usage of bitsadmin downloading a file to a suspicious target folder - **Level**: N/A - **Status**: test - **Author**: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) - **Date**: 2022-06-
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: File Download Via Bitsadmin

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-284`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # File Download Via Bitsadmin Detects usage of bitsadmin downloading a file - **Level**: N/A - **Status**: test - **Author**: Michael Haag, FPT.EagleEye - **Date**: 2017-03-09 - **Category**: Windows ## Rule 'yaml title: File Download Via Bitsadmin id: d059842b-6b9d-4ed1-b5c3-5
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: File With Suspicious Extension Downloaded Via Bitsadmin

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-284`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # File With Suspicious Extension Downloaded Via Bitsadmin Detects usage of bitsadmin downloading a file with a suspicious extension - **Level**: N/A - **Status**: test - **Author**: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) - **Date**: 2022-06-28 -
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
