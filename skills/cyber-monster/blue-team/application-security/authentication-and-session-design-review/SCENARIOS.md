# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`authentication-and-session-design-review`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Az - Local Cloud Credentials

- **Provenance:** Source: `CYBER_CPT/hacktricks_cloud`
- **Context / Surface:** Cloud Security Guide (en)
- **Root Cause / Analysis:** Az - Local Cloud Credentials Local Token Storage and Security Considerations Azure CLI (Command-Line Interface) Tokens and sensitive data are stored locally by Azure CLI, raising security concerns: 1.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Openstack Magnum Unsafe Credential Handling

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-287`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Openstack Magnum Unsafe Credential Handling Openstack Magnum Unsafe Credential Handling - **OSV ID**: GHSA-793v-r35j-9rp9 - **CVE**: CVE-2016-7404 - **CVSS**: CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - **Published**: 2022-05-24T16:48:34Z - **Modified**: 2024-02-16T08:10:18.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Openstack Magnum Unsafe Credential Handling

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-287`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** OpenStack Magnum passes OpenStack credentials into the Heat templates creating its instances. While these should just be used for retrieving the instances' SSL certificates, they allow full API access, though and can be used to perform any API operation the user is authorized to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
