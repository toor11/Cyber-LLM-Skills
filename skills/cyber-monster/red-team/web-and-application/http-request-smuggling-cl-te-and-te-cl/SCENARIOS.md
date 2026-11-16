# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`http-request-smuggling-cl-te-and-te-cl`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Basic CL.TE - HTTP request smuggling

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-444`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Basic CL.TE - HTTP request smuggling 'yaml id: cl-te-http-smuggling info: name: Basic CL.TE - HTTP request smuggling author: pdteam,akincibor severity: low description: / Detected a potential CL.TE request smuggling condition where conflicting Content-Length and Transfer-Enco
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: Basic TE.CL - HTTP Request Smuggling

- **Provenance:** Source: `CYBER_CPT/nuclei_templates` | CWE: `CWE-444`
- **Context / Surface:** Source: nuclei_templates (en)
- **Root Cause / Analysis:** # Basic TE.CL - HTTP Request Smuggling - **Template ID**: te-cl-http-smuggling - **Severity**: low - **Author**: pdteam,akincibor - **Category**: Http - **Tags**: te-cl, smuggling 'yaml id: te-cl-http-smuggling info: name: Basic TE.CL - HTTP Request Smuggling author: pdteam,aki
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: actix-http has HTTP/1.1 CL.TE Request Smuggling

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-444`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** A vulnerability in 'actix-http's HTTP/1.1 request parser allows an unauthenticated remote client to smuggle requests in deployments where a front-end HTTP intermediary and the Actix backend disagree about whether 'Content-Length' or 'Transfer-Encoding: chunked' defines the reque
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
