# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`session-and-token-lifecycle-revocation-gaps`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Vikunja Vulnerable to Account Takeover via Password Reset Token Reuse

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-384`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Vikunja Vulnerable to Account Takeover via Password Reset Token Reuse - **OSV ID**: GHSA-rfjg-6m84-crj2 - **CVE**: CVE-2026-28268 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H - **Published**: 2026-02-28T01:59:28Z - **Modified**: 2026-03-23T04:56:16.699144280Z - **Af
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: FastMCP OAuth Proxy token reuse across MCP servers

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-384`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # FastMCP OAuth Proxy token reuse across MCP servers FastMCP OAuth Proxy token reuse across MCP servers - **OSV ID**: GHSA-5h2m-4q8j-pqpj - **CVE**: CVE-2025-69196 - **Published**: 2026-03-16T15:14:55Z - **Modified**: 2026-03-16T22:01:29.783799Z - **Affected Packages**: fastmcp -
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Vikunja Vulnerable to Account Takeover via Password Reset Token Reuse

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-384`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** **Summary** A critical business logic vulnerability exists in the password reset mechanism of vikunja/api that allows password reset tokens to be reused indefinitely. Due to a failure to invalidate tokens upon use and a critical logic bug in the token cleanup cron job, reset toke
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: CSRF Token Reuse Vulnerability

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-384`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** A Cross-Site Request Forgery (CSRF) vulnerability has been identified in the application, which allows an attacker to inject arbitrary values and forge malicious requests on behalf of a user. This vulnerability can allow an attacker to inject arbitrary values without any authenti
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: CSRF Token Reuse Vulnerability

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-384`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # CSRF Token Reuse Vulnerability CSRF Token Reuse Vulnerability - **OSV ID**: GHSA-94w9-97p3-p368 - **CVE**: CVE-2023-45128 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L - **Published**: 2023-10-17T12:40:37Z - **Modified**: 2023-11-08T04:13:36.712052Z - **Affected Pack
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: CSRF token reuse vulnerability in github.com/gofiber/fiber/v2

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-384`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # CSRF token reuse vulnerability in github.com/gofiber/fiber/v2 CSRF token reuse vulnerability in github.com/gofiber/fiber/v2 - **OSV ID**: GO-2023-2115 - **CVE**: CVE-2023-45128 - **Published**: 2023-10-24T16:57:01Z - **Modified**: 2024-05-20T16:03:47Z - **Affected Packages**: g
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
