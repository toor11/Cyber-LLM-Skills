# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`waf-bypass-and-payload-obfuscation`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: MobileIron Unauthenticated RCE on mdm.qiwi.com with WAF bypass

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2020-15505`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Last week, details about 3 CVEs affecting **MobileIron MDM** product were disclosed. When combined, an attacker can achieve unauthenticated remote code execution with arbitrary Java deserialization vector : - CVE-2020-15505 - Remote Code Execution - CVE-2020-15506 -...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Stored XSS in ' Section and WAF Bypass

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary Stored Cross-site Scripting (XSS) is the most dangerous type of Cross Site Scripting. Web applications that allow users to store data are potentially exposed to this type of attack.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: URL filter bypass in Enterprise Grid

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** URL filter bypass in Enterprise Grid Description Slack Enterprise Grid seems to be able to add arbitrary column to the profile of the account. In my company there is a おすすめランチ (My Favorite Lunch) column, and we can set the URL of the website and Display text.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Self-Stored XSS - Chained with login/logout CSRF

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** > NOTE! This report explains taking over an account in a single click by chaining stored XSS, WAF bypass, login and logout CSRF. **Summary:** Attacker can takeover someone's account by stealing their facebook / google login tokens chaining multiple vulnerabilities.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Reflected XSS on the data.gov (WAF bypass+ Chrome XSS Auditor bypass+ works in all browsers)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description Hello. I discovered Cross-Site scripting issue on the https://www.data.gov/local/ endpoint. The issue can be site-wide, and exploitable in any place, where pagination exist.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: SSRF via potential filter bypass with too lax local domain checking

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi. Reviewing the code for filtering for ssrf, in 'preventLocalAddress', we can see that it calls the function 'ThrowIfLocalAddress()'.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Open Redirect filter bypass through '\' character via URL parameter

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I hope I find you all safe and good regarding those hard times nowadays. Summary: Found an Open Redirect vulnerability on http://meta.myndr.net by bypassing the trusted domain filter using a '\' character.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: xss filter bypass [polldaddy]

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, previously reported xss https://hackerone.com/reports/107405 which is fixed, but i am able to bypass that fix. Payload for bypass : '<a href="javascript&colon;alert&lpar;document&period;domain&rpar;">Click Here' Steps: - Login into Polldaddy account polldaddy.com - go to...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
