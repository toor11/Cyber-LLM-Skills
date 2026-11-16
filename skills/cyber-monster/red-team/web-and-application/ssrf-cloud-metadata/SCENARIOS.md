# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssrf-cloud-metadata`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: SSRF in Exchange leads to ROOT access in all instances

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The Exploit Chain - How to get root access on all Shopify instances 1 - Access Google Cloud Metadata - 1: Create a store (partners.shopify.com) - 2: Edit the template 'password.liquid' and add the following content: html ...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: IMDS Abused: Hunting Rare Behaviors to Uncover Exploits

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-918`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** # **Introduction** In the world of cloud security, the Instance Metadata Service (IMDS) is a fundamental building block. It’s designed to provide virtual machines with a simple way to securely get temporary credentials and critical data without hardcoding secrets. But what happen
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Ech0: Unauthenticated SSRF in GetWebsiteTitle allows access to internal services and cloud metadata

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-918`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary The 'GET /api/website/title' endpoint accepts an arbitrary URL via the 'website_url' query parameter and makes a server-side HTTP request to it without any validation of the target host or IP address. The endpoint requires no authentication. An attacker can use this to
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Craft CMS: Cloud Metadata SSRF Protection Bypass via IPv6 Resolution

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-918`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** The SSRF validation in Craft CMS's GraphQL Asset mutation uses 'gethostbyname()', which only resolves IPv4 addresses. When a hostname has only AAAA (IPv6) records, the function returns the hostname string itself, causing the blocklist comparison to always fail and completely bypa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Craft CMS has Cloud Metadata SSRF Protection Bypass via DNS Rebinding

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-918`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Craft CMS has Cloud Metadata SSRF Protection Bypass via DNS Rebinding - **OSV ID**: GHSA-gp2f-7wcm-5fhx - **CVE**: CVE-2026-27127 - **Published**: 2026-02-23T22:16:01Z - **Modified**: 2026-02-28T05:14:37.829487Z - **Affected Packages**: craftcms/cms - **Ecosystem**: Packagist #
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Craft CMS: Cloud Metadata SSRF Protection Bypass via IPv6 Resolution

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-918`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Craft CMS: Cloud Metadata SSRF Protection Bypass via IPv6 Resolution - **OSV ID**: GHSA-v2gc-rm6g-wrw9 - **CVE**: CVE-2026-27129 - **Published**: 2026-02-24T15:51:07Z - **Modified**: 2026-02-24T20:59:13.352088Z - **Affected Packages**: craftcms/cms - **Ecosystem**: Packagist Th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: pyLoad: Server-Side Request Forgery via Download Link Submission Enables Cloud Metadata Exfiltration

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-918`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # pyLoad: Server-Side Request Forgery via Download Link Submission Enables Cloud Metadata Exfiltration - **OSV ID**: GHSA-m74m-f7cr-432x - **CVE**: CVE-2026-33992 - **Published**: 2026-03-27T18:00:43Z - **Modified**: 2026-03-30T20:35:02.160208Z - **Affected Packages**: pyload-ng
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
