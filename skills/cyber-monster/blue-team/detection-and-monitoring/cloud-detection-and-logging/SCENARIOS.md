# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cloud-detection-and-logging`](SKILL.md) | Family: **Detection and Monitoring**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: View any user email using the Team's audit log section

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** Hello team, I decided to do some further testing, and I came across another endpoint that can be used to reveal user emails. Steps To Reproduce 1. Create a demo in your account https://hackerone.com/teams/new/sandbox 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Runtime API And Daemon Exposure

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Runtime API And Daemon Exposure Overview Many real container compromises do not begin with a namespace escape at all. They begin with access to the runtime control plane.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: AWS - EKS Enum

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** AWS - EKS Enum EKS Amazon Elastic Kubernetes Service (Amazon EKS) is designed to eliminate the need for users to install, operate, and manage their own Kubernetes control plane or nodes.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Linux & Cloud Detection Engineering - TeamPCP Container Attack Scenario

- **Provenance:** Source: `CYBER_CPT/elastic_security` | CWE: `CWE-778`
- **Context / Surface:** Source: elastic_security (en)
- **Root Cause / Analysis:** # Linux & Cloud Detection Engineering - TeamPCP Container Attack Scenario This publication provides a real-world walkthrough of TeamPCP's multi-stage container compromise, demonstrating how Elastic's D4C surfaces runtime signals across each stage of the attack chain. ## Introduct
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: AWS - CloudTrail Enum

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud` | CWE: `CWE-778`
- **Context / Surface:** Source: hacktricks_cloud (en)
- **Root Cause / Analysis:** # AWS - CloudTrail Enum ## **CloudTrail** AWS CloudTrail **records and monitors activity within your AWS environment**. It captures detailed **event logs**, including who did what, when, and from where, for all interactions with AWS resources. This provides an audit trail of chan
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: How to use the new CloudTrail network activity events for AWS VPC Endpoints

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-778`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** # Takeaways * Everyone that uses VPC Endpoints should enable network activity events for 'VpceAccessDenied' errors. * For those that have not yet applied restrictive VPC Endpoint Policies, Network Activity events can ensure existing functionality will not be disrupted. * In some
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Wrangling the M365 UAL with PowerShell and SOF-ELK (Part 1 of 3)

- **Provenance:** Source: `CYBER_CPT/blackhills` | CWE: `CWE-778`
- **Context / Surface:** Source: blackhills (en)
- **Root Cause / Analysis:** # Wrangling the M365 UAL with PowerShell and SOF-ELK (Part 1 of 3) When it comes to M365 audit and investigation, the “Unified Audit Log” (UAL) is your friend. It can be surly, obstinate, and wholly inadequate, but your friend nonetheless. Sadly, depending upon licensing and rete
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB Sherlock: Nubilum-1

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-778`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** ![Nubilum-1] (/icons/sherlock-nubilum-1.png) Nublium-1 is all about cloud forensics, specifically a compromised AWS account that leads to multiple EC2 VM instances, including one acting as a PoshC2 server. I’ll work through the CloudTrail logs in a Splunk instance (run via Docker
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
