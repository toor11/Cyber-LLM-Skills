# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`endpoint-detection-and-edr-operations`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Break Process Trees

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise`
- **Context / Surface:** ATT&CK Technique (en)
- **Root Cause / Analysis:** Break Process Trees **ID**: T1036.009 **Type**: Technique **Tactics**: stealth **Platforms**: Linux, macOS An adversary may attempt to evade process tree-based analysis by modifying executed malware's parent process ID (PPID).
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Evade EDR External Connections via Firewall Rules

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Evade EDR External Connections via Firewall Rules Creating firewall rules to block outgoing network connections keeps your EDR (Endpoint Detection and Response) tool from connecting to its main server.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: Endpoint Detection and Response

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-778`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Endpoint Detection and Response Endpoint Detection and Response (EDR) is a security solution that combines real-time monitoring, data collection, and advanced analytics to detect, investigate, and respond to cyber threats at the endpoint level. Leveraging machine learning algor
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Explorer Process Tree Break

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-778`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Explorer Process Tree Break - **Level**: N/A - **Status**: test - **Author**: Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems), @gott_cyber - **Date**: 2019-06-29 - **Category**: Windows ## Rule 'yaml title: Explorer Process Tree Break id: 949f1ffb-6e
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Break Process Trees

- **Provenance:** Source: `CYBER_CPT/mitre_attack_enterprise` | CWE: `CWE-778`
- **Context / Surface:** Source: mitre_attack_enterprise (en)
- **Root Cause / Analysis:** # Break Process Trees **ID**: T1036.009 **Type**: Technique **Tactics**: stealth **Platforms**: Linux, macOS An adversary may attempt to evade process tree-based analysis by modifying executed malware's parent process ID (PPID). If endpoint protection software leverages the “pare
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Versa Director API Endpoint Detection

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-778`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Versa Director API Endpoint Detection Versa Director API Endpoint (Unauthorized) Detection - **Template ID**: versa-director-api - **Severity**: info - **Author**: c-sh0 - **Category**: Http - **Tags**: api, versa, tech, discovery 'yaml id: versa-director-api info: name: Vers
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: IBM QRadar EDR - Endpoint Detection and Response Solutions

- **Provenance:** Source: `CYBER_CPT/secwiki` | CWE: `CWE-778`
- **Context / Surface:** Source: secwiki (en)
- **Root Cause / Analysis:** 1. [Home] (/) 2. [Products] (/products) 3. QRadar EDR # IBM QRadar EDR Secure endpoints from cyberattacks, detect anomalous behavior and remediate in near real time [Book a live demo] (https://www.ibm.com/account/reg/signup?formid=DEMO-securityqradaredr) ![QRadar Highlight EDR dashb
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Tailmon-EDR: Tailmon主机安全卫士 / Tailmon Endpoint Detection and Response

- **Provenance:** Source: `CYBER_CPT/secwiki` | CWE: `CWE-778`
- **Context / Surface:** Source: secwiki (en)
- **Root Cause / Analysis:** [登录] (/login) [注册] (/signup) * [开源] (/explore) * [企业版] (/enterprises) * [高校版] (/education) * [搜索] (/search) * [帮助中心] (/help) * [使用条款] (/terms) * [关于我们] (/about_us) [![Gitee - 基于 Git 的代码托管和研发协作平台] (/static/images/logo-black.svg?t=158106664 "Gitee - 基于 Git 的代码托管和研发协作平台") ![Gitee - 基于 Git 的代码
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
