# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`authorization-and-idor-tenant-isolation`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: GitLab CI runner can read and poison cache of all other projects

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The GitLab CI runner allows users to cache files and directories in between runs. These files are stored in a ZIP file and uploaded to a shared cache instance.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: The user, who was deleted from Github Organization, still can access all functions of federalist, in case

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description Hi. I found a non-critical session management bug, which still can have serious impact in some scenarios. When user perform login to the Federalist through Github, federalist checks his Organization ID (but only upon login).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Kyverno APICall SSRF Vulnerability Leading to Multi-Tenant Isolation Breach

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-639`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary Kyverno's APICall feature contains a Server-Side Request Forgery (SSRF) vulnerability that allows users with Policy creation permissions to access arbitrary internal resources through Kyverno's high-privilege ServiceAccount. In multi-tenant Kubernetes environments, th
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Introducing PEACH, a tenant isolation framework for cloud applications

- **Provenance:** Source: `CYBER_CPT/wiz_research` | CWE: `CWE-639`
- **Context / Surface:** Source: wiz_research (en)
- **Root Cause / Analysis:** Over the past year and a half, Wiz researchers and other members of the cloud security community discovered several cross-tenant vulnerabilities in various multi-tenant cloud applications (including [ExtraReplica] (https://www.wiz.io/blog/wiz-research-discovers-extrareplica-cross-
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Microsoft Azure Domain Tenant ID - Detect

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-639`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Microsoft Azure Domain Tenant ID - Detect Microsoft Azure Domain Tenant ID was detected. - **Template ID**: azure-domain-tenant - **Severity**: info - **Author**: V0idC0de - **Category**: Http - **Tags**: azure, microsoft, cloud, exposure, vuln 'yaml id: azure-domain-tenant i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: A SQL injection vulnerability in Mybatis plus below 3.5.3.1 allows remote attackers to execute arbit

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-639`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # A SQL injection vulnerability in Mybatis plus below 3.5.3.1 allows remote attackers to execute arbitrary SQL commands via the tenant ID valuer. NOTE: the vendor's position is that this can only occur - **CVE**: CVE-2023-25330 - **Exploit Type**: InTheWild - **Exploit ID**: InTh
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
