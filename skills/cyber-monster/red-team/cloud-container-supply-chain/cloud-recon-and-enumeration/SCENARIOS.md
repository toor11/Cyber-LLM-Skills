# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cloud-recon-and-enumeration`](SKILL.md) | Family: **Cloud, Container and Supply Chain**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Cloud Enumeration

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-269`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # Cloud Enumeration O365spray is a username enumeration and password spraying tool aimed at Microsoft Office 365. Validate if our target domain is using Office 365. 'bash python3 o365spray.py --validate --domain msplaintext.xyz ' If Valid => Identify usernames 'bash python3
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: CloudFox: Cloud Enumeration for Penetration Testing

- **Provenance:** Source: `CYBER_CPT/bishop_fox` | CWE: `CWE-269`
- **Context / Surface:** Source: bishop_fox (en)
- **Root Cause / Analysis:** ## CloudFox: Cloud Enumeration for Penetration Testing > **Jargon: Enumeration** — The systematic process of discovering and listing all resources, users, and configurations within a target environment. > **Jargon: Penetration Testing** — Authorized simulated cyberattacks perform
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Azure Databases - Cloud Enumeration

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-269`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Azure Databases - Cloud Enumeration - **Template ID**: azure-db-enum - **Severity**: info - **Author**: initstring - **Category**: Cloud - **Tags**: cloud, enum, cloud-enum, azure, dns, discovery 'yaml id: azure-db-enum info: name: Azure Databases - Cloud Enumeration author:
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Azure Virtual Machines - Cloud Enumeration

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-269`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Azure Virtual Machines - Cloud Enumeration - **Template ID**: azure-vm-cloud-enum - **Severity**: info - **Author**: initstring - **Category**: Cloud - **Tags**: cloud, cloud-enum, azure, fuzz, enum, dns, discovery 'yaml id: azure-vm-cloud-enum info: name: Azure Virtual Machi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Potential Bucket Enumeration on AWS

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-269`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Potential Bucket Enumeration on AWS Looks for potential enumeration of AWS buckets via ListBuckets. - **Level**: N/A - **Status**: test - **Author**: Christopher Peacock @securepeacock, SCYTHE @scythe_io - **Date**: 2023-01-06 - **Category**: Cloud ## Rule 'yaml title: Potent
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
