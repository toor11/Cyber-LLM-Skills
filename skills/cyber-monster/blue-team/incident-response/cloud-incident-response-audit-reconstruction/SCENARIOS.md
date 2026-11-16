# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cloud-incident-response-audit-reconstruction`](SKILL.md) | Family: **Incident Response**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Runtime API And Daemon Exposure

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Runtime API And Daemon Exposure Overview Many real container compromises do not begin with a namespace escape at all. They begin with access to the runtime control plane.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: AWS - EKS Enum

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** AWS - EKS Enum EKS Amazon Elastic Kubernetes Service (Amazon EKS) is designed to eliminate the need for users to install, operate, and manage their own Kubernetes control plane or nodes.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: HTB Sherlock: BFT

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-778`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** BFT is all about analysis of a Master File Table (MFT). I’ll use Zimmerman tools MFTECmd and Timeline Explorer to find where a Zip archive was downloaded from Google Drive. It is then unzipped to get another zip, which is unzipped to get another zip. That final zip has a Windows
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Code to Cloud Attacks: From Github PAT to Cloud Control Plane

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-778`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** Threat actors are targeting GitHub Personal Access Tokens (PAT) as high-value entry points, leveraging compromised PATs to gain initial access to victim cloud environments. Historically, compromised PATs were used to identify and obtain secrets hard-coded in source code. However,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Making Sense of Kubernetes Initial Access Vectors Part 2 - Data Plane

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-778`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** This is the second part of our two-blog series, where we explore various initial access vectors into Kubernetes environments, analyze the associated attack angles, and clarify the relevant risks. # Taxonomy [In the first blog] (https://www.wiz.io/blog/making-sense-of-kubernetes-in
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Making Sense of Kubernetes Initial Access Vectors Part 1 – Control Plane

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-778`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** # Motivation Kubernetes (K8s) is a complex distributed system designed to run containerized workloads in a scalable and manageable way. It’s now the default method for deploying workloads in cloud-native environments. Thanks to its flexibility and extensibility, Kubernetes has pr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: TryHackMe / IR Timeline Analysis / WriteUp

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-778`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe / IR Timeline Analysis / WriteUp ## Learn about timeline analysis using various tools and scenarios. Task 1 Introduction In digital investigations, the more forensic data you have, the more complex things will be to process and analyze. It is, therefore, important to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: MyBB Timeline Plugin 1.0 - Cross-Site Scripting / CSRF

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-778`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # MyBB Timeline Plugin 1.0 - Persistent Cross-Site Scripting / / / / / --- / --- / --- / / EKU-ID: 53471 / CVE: / OSVDB-ID: / / Author: 0xB9 / Published: 2021-01-25 / Verified: ![Not Verified] (/images/cancel.png) / / Download: / / / / / / --- / / Rating☆☆☆☆☆ / [![] (/images/prev.p
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
