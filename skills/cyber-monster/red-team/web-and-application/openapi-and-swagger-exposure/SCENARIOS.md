# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`openapi-and-swagger-exposure`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Reflected XSS on developers.zomato.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** There is a vulnerability in https://developers.zomato.com/documentation due to an old version of Swagger UI **Step to reproduce:** - Create an endpoint containing : json {"swagger":"2.0","info":{"description":"This is a sample server Petstore server.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: A Cascading Style Sheets (CSS) injection vulnerability in Swagger UI before 3.23.11 allows attackers

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # A Cascading Style Sheets (CSS) injection vulnerability in Swagger UI before 3.23.11 allows attackers to use the Relative Path Overwrite (RPO) technique to perform CSS-based input field value exfiltrat - **CVE**: CVE-2019-17495 - **Exploit Type**: InTheWild - **Exploit ID**: InT
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: LiteLLM API - Swagger UI Detection

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-200`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # LiteLLM API - Swagger UI Detection / - **Template ID**: litellm-swagger-detect - **Severity**: info - **Author**: rxerium - **Category**: Http - **Tags**: tech, litellm, swagger, api, ai, llm 'yaml id: litellm-swagger-detect info: name: LiteLLM API - Swagger UI Detection auth
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Reflected XSS in Gotify's /docs via import of outdated Swagger UI

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-200`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Reflected XSS in Gotify's /docs via import of outdated Swagger UI Reflected XSS in Gotify's /docs via import of outdated Swagger UI - **OSV ID**: GHSA-3244-8mff-w398 - **Published**: 2023-01-10T22:48:43Z - **Modified**: 2024-08-20T20:59:06.646301Z - **Affected Packages**: githu
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: fastify-swagger-ui is a Fastify plugin for serving Swagger UI. Prior to 2.1.0, the default configur

- **Provenance:** Source: `CYBER_CPT/go_exploitdb` | CWE: `CWE-200`
- **Context / Surface:** Source: go_exploitdb (en)
- **Root Cause / Analysis:** # fastify-swagger-ui is a Fastify plugin for serving Swagger UI. Prior to 2.1.0, the default configuration of '@fastify/swagger-ui' without 'baseDir' set will lead to all files in the module's director - **CVE**: CVE-2024-22207 - **Exploit Type**: Nuclei - **Exploit ID**: Nuclei-
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Reflected XSS in Gotify's /docs via import of outdated Swagger UI

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-200`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Impact Gotify exposes an outdated instance of the [Swagger UI] (https://swagger.io/tools/swagger-ui/) API documentation frontend at '/docs' which is susceptible to reflected XSS attacks when loading external Swagger config files. Specifically, the DOMPurify version included wi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
