# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`http-request-smuggling-te-te-and-obfuscation`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTTP Request Smuggling due to accepting space before colon

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** The 'llhttp' parser in the 'http'module in Node 16.3.0 accepts requests with a space (SP) right after the header name before the colon. This can lead to HTTP Request Smuggling (HRS).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: h3 v1 has Request Smuggling (TE.TE) issue

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-444`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** I was digging into h3 v1 (specifically v1.15.4) and found a critical HTTP Request Smuggling vulnerability. Basically, 'readRawBody' is doing a strict case-sensitive check for the Transfer-Encoding header. It explicitly looks for "chunked", but per the RFC, this header should be c
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: h3 v1 has Request Smuggling (TE.TE) issue

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-444`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # h3 v1 has Request Smuggling (TE.TE) issue - **OSV ID**: GHSA-mp2g-9vg9-f4cg - **CVE**: CVE-2026-23527 - **CVSS**: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L - **Published**: 2026-01-15T20:10:51Z - **Modified**: 2026-04-13T17:15:15.108956Z - **Affected Packages**: h3 - **Ecosy
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
