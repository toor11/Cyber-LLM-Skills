# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`business-logic-flaws-quota-and-rate`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Rate Limit Bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-840`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Rate Limit Bypass ## Rate limit bypass techniques ### Exploring Similar Endpoints Attempts should be made to perform brute force attacks on variations of the targeted endpoint, such as '/api/v3/sign-up', including alternatives like '/Sing-up', '/SignUp', '/singup', '/api/v1/sig
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: SandboxJS has an execution-quota bypass (cross-sandbox currentTicks race) in SandboxJS timers

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-840`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary Assumed repo path is '/Users/zwique/Downloads/SandboxJS-0.8.34' (no '/Users/zwique/Downloads/SandboxJS' found). A global tick state ('currentTicks.current') is shared between sandboxes. Timer string handlers are compiled at execution time using that global tick state r
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Froxlor has a Reseller Domain Quota Bypass via Unvalidated adminid Parameter in Domains.add()

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-840`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary In 'Domains.add()', the 'adminid' parameter is accepted from user input and used without validation when the calling reseller does not have the 'customers_see_all' permission. This allows a reseller to attribute newly created domains to any other admin, bypassing their
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: SandboxJS has an execution-quota bypass (cross-sandbox currentTicks race) in SandboxJS timers

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-840`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # SandboxJS has an execution-quota bypass (cross-sandbox currentTicks race) in SandboxJS timers SandboxJS has an execution-quota bypass (cross-sandbox currentTicks race) in SandboxJS timers - **OSV ID**: GHSA-7p5m-xrh7-769r - **CVE**: CVE-2026-32723 - **Published**: 2026-03-16T16
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Parse Server has a rate limit bypass via batch request endpoint

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-840`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Parse Server has a rate limit bypass via batch request endpoint - **OSV ID**: GHSA-775h-3xrc-c228 - **CVE**: CVE-2026-30972 - **Published**: 2026-03-11T00:21:51Z - **Modified**: 2026-03-14T03:41:04.967339Z - **Affected Packages**: parse-server - **Ecosystem**: npm ### Impact Pa
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Misskey has a login rate limit bypass via spoofed X-Forwarded-For header

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-840`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Misskey has a login rate limit bypass via spoofed X-Forwarded-For header Misskey has a login rate limit bypass via spoofed X-Forwarded-For header - **OSV ID**: GHSA-wwrj-3hvj-prpm - **CVE**: CVE-2025-66482 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L - **Published**
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
