# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`credential-dumping-lsass-and-memory`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: Heist

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-522`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Heist] (https://0xdfimages.gitlab.io/img/heist-cover.png) Heist brought new concepts I hadn’t seen on HTB before, yet keep to the easy difficulty. I’ll start by find a Cisco config on the website, which has some usernames and password hashes. After recovering the passwords, I’ll
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Procdump

- **Provenance:** Source: `CYBER_CPT/lolbas` | CWE: `CWE-522`
- **Context / Surface:** Source: lolbas (en)
- **Root Cause / Analysis:** # [..] (/) /Procdump.exe [Star] (https://github.com/LOLBAS-Project/LOLBAS) [Execute (DLL)] (/lolbas/OtherMSBinaries/Procdump/#execute) SysInternals Memory Dump Tool ### Paths: * no default ### Resources: * https://twitter.com/ajpc500/status/1448588362382778372?s=20 ### Acknowledge
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HackTool - HandleKatz LSASS Dumper Execution

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-522`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # HackTool - HandleKatz LSASS Dumper Execution Detects the use of HandleKatz, a tool that demonstrates the usage of cloned handles to Lsass in order to create an obfuscated memory dump of the same ## Rule 'yaml title: HackTool - HandleKatz LSASS Dumper Execution id: ca621ba5-54
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Renamed ProcDump Execution

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-522`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Renamed ProcDump Execution - **Level**: N/A - **Status**: test - **Author**: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems) - **Date**: 2019-11-18 - **Category**: Windows ## Rule 'yaml title: Renamed ProcDump Execution id: 4a0b2c7e-7cb2-495d-8b63-5f
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: LSASS Dump Keyword In CommandLine

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-522`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # LSASS Dump Keyword In CommandLine - **Level**: N/A - **Status**: test - **Author**: E.M. Anhaus, Tony Lambert, oscd.community, Nasreddine Bencherchali (Nextron Systems) - **Date**: 2019-10-24 - **Category**: Windows ## Rule 'yaml title: LSASS Dump Keyword In CommandLine id: f
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
