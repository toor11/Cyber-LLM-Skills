# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cross-site-scripting-filter-and-context-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: XSS in gist integration

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** 1. Create a gist called: "> 2. have gist integration enabled and put a link in a slack chat 3. Visit the 'raw' or 'new window' pages for this gist, for example: https://outpost.slack.com/files/zemnmez/F029MDY33/___svg_onload_alert_1__
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: xss filter bypass [polldaddy]

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, previously reported xss https://hackerone.com/reports/107405 which is fixed, but i am able to bypass that fix. Payload for bypass : '<a href="javascript&colon;alert&lpar;document&period;domain&rpar;">Click Here' Steps: - Login into Polldaddy account polldaddy.com - go to...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Stored XSS in Name of Team Member Invitation

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** hello team i have found an stored in add team member Step to reproduce 1. Go to https://localizestaging.com/organization/team?filter=all 2. click on add team member 3. On the name, enter payload: 4.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: XSS Filter Bypass

- **Provenance:** Source: `CYBER_CPT/payloads_all_the_things` | CWE: `CWE-79`
- **Context / Surface:** Source: payloads_all_the_things (en)
- **Root Cause / Analysis:** # XSS Filter Bypass ## Summary ## Bypass Case Sensitive To bypass a case-sensitive XSS filter, you can try mixing uppercase and lowercase letters within the tags or function names. 'javascript alert(1) alert(1) ' Since many XSS filters only r
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: phpMyFAQ: SVG Sanitizer Bypass via HTML Entity Encoding Leads to Stored XSS and Privilege Escalation

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-79`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # phpMyFAQ: SVG Sanitizer Bypass via HTML Entity Encoding Leads to Stored XSS and Privilege Escalation - **OSV ID**: GHSA-5crx-pfhq-4hgg - **CVE**: CVE-2026-34974 - **CVSS**: CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N - **Published**: 2026-04-01T23:42:47Z - **Modified**: 2026-0
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Happy DOM: VM Context Escape can lead to Remote Code Execution

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-79`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** # Escape of VM Context gives access to process level functionality ## Summary Happy DOM v19 and lower contains a security vulnerability that puts the owner system at the risk of RCE (Remote Code Execution) attacks. A Node.js VM Context is not an isolated environment, and if the u
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Happy DOM: VM Context Escape can lead to Remote Code Execution

- **Provenance:** Source: `CYBER_CPT/osv` | CWE: `CWE-79`
- **Context / Surface:** Source: osv (en)
- **Root Cause / Analysis:** # Happy DOM: VM Context Escape can lead to Remote Code Execution Happy DOM: VM Context Escape can lead to Remote Code Execution - **OSV ID**: GHSA-37j7-fg3j-429f - **CVE**: CVE-2025-61927 - **Published**: 2025-10-10T23:46:42Z - **Modified**: 2025-10-13T15:48:53Z - **Affected Pack
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: Internet Explorer 9 XSS Filter Bypass

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-79`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** ## HackCTF Pwnable [rtl_world] 풀이 32bit ELF rtl로 푼다. IDA를 이용해 system()의 주소와 "/bin/sh"의 주소를 쉽게 구할 수 있다. system() "/bin/sh" "/bin/sh"는 main함수에 있는 "/bin/sh"을 따라가면 된다. main 함수 5번에서 bof가 일어난다. buf의 위치는 bp-8C이다. 0x8C = 140 payload = dummy[140] +dummy sfp[4] + system() + dummy[4] + bins
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
