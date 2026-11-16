# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`active-directory-enumeration-gpo-and-administrative-discovery`](SKILL.md) | Family: **Network, Active Directory and Endpoint**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Privileged Groups

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-284`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Privileged Groups ## Well Known groups with administration privileges - **Administrators** - **Domain Admins** - **Enterprise Admins** ## Account Operators This group is empowered to create accounts and groups that are not administrators on the domain. Additionally, it enables
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Standard User In High Privileged Group

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-284`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # Standard User In High Privileged Group Detect standard users login that are part of high privileged groups such as the Administrator group - **Level**: N/A - **Status**: test - **Author**: frack113 - **Date**: 2023-01-13 - **Category**: Windows ## Rule 'yaml title: Standard U
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: User Added To Highly Privileged Group

- **Provenance:** Source: `CYBER_CPT/sigmahq` | CWE: `CWE-284`
- **Context / Surface:** Source: sigmahq (en)
- **Root Cause / Analysis:** # User Added To Highly Privileged Group Detects addition of users to highly privileged groups via "Net" or "Add-LocalGroupMember". - **Level**: N/A - **Status**: test - **Author**: Nasreddine Bencherchali (Nextron Systems) - **Date**: 2024-02-23 - **Category**: Windows ## Rule '
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
