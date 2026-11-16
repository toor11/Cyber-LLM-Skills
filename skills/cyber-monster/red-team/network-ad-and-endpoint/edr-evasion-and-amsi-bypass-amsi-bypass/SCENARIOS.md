# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`edr-evasion-and-amsi-bypass-amsi-bypass`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Windows - AMSI Bypass

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-693`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Windows - AMSI Bypass ## List AMSI Providers * List providers with : 'Get-ChildItem -Path 'HKLM:\SOFTWARE\Microsoft\AMSI\Providers\' * Find software from CLSID 'ps1 Get-ChildItem -Path 'HKLM:\SOFTWARE\Classes\CLSID\{2781761E-28E0-4109-99FE-B9D127C57AFE}' Name Property ---- -
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: AMSI Bypass Pattern Assembly GetType

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-693`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # AMSI Bypass Pattern Assembly GetType Detects code fragments found in small and obfuscated AMSI bypass PowerShell scripts - **Level**: N/A - **Status**: test - **Author**: Florian Roth (Nextron Systems) - **Date**: 2022-11-09 - **Category**: Windows ## Rule 'yaml title: AMSI B
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Potential AMSI Bypass Script Using NULL Bits

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-693`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Potential AMSI Bypass Script Using NULL Bits Detects usage of special strings/null bits in order to potentially bypass AMSI functionalities - **Level**: N/A - **Status**: test - **Author**: Nasreddine Bencherchali (Nextron Systems) - **Date**: 2023-01-04 - **Category**: Windows
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Potential Persistence Via New AMSI Providers - Registry

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-693`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Potential Persistence Via New AMSI Providers - Registry - **Level**: N/A - **Status**: test - **Author**: Nasreddine Bencherchali (Nextron Systems) - **Date**: 2022-07-21 - **Category**: Windows 'yaml title: Potential Persistence Via New AMSI Providers - Registry id: 33efc23c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Removal Of AMSI Provider Registry Keys

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-693`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Removal Of AMSI Provider Registry Keys Detects the deletion of AMSI provider registry key entries in HKLM\Software\Microsoft\AMSI. This technique could be used by an attacker in order to disable AMSI inspection. - **Level**: N/A - **Status**: test - **Author**: frack113 - **Dat
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
