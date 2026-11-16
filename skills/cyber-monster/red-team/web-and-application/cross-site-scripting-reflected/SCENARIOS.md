# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cross-site-scripting-reflected`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Reflected XSS on https://www.glassdoor.com/employers/sem-dual-lp/

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** There is a reflected XSS on https://www.glassdoor.com/employers/sem-dual-lp/ through the utm_source parameter. By using URL encoding I was able to bypass the WAF.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Reflected XSS on www.hackerone.com and resources.hackerone.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Good day :) I hope your doing as well as can be during these difficult times. I have found xss at 2 endpoints: https://www.hackerone.com/resources/ and https://resources.hackerone.com The payloads that work are here:...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Reflected XSS on www.hackerone.com via Wistia embed code

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** The HackerOne marketing site uses Wistia to host and embed videos using html snippets similar to the following: html <script src="https://fast.wistia.com/embed/medias/t306dw04gl.jsonp" async="" > <script src="https://fast.wistia.com/assets/external/E-v1.js"...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Stored XSS on reports.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** Stored XSS can be submitted on reports, and anyone who will check the report the XSS will trigger. **Description:** Stored XSS, also known as persistent XSS, is the more damaging than non-persistent XSS.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Config override using non-validated query parameter allows at least reflected XSS by injecting configurat

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, First, I just want to say after spending a few days on your assets that I'm really impressed by the high security standard of the apps exposed. It has not been easy to find issues.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Reflected Cross site Scripting (XSS) on www.starbucks.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** Reflected Cross site Scripting (XSS) on https://www.starbucks.com/account/signin?ReturnUrl **Description:** The attacker can execute javascript on the victims account just after the authentication process.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: XSS in www.shopify.com/markets?utm_source=

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, hope you are having a good day :) Summary: I found a reflected XSS in 'www.shopify.com/markets' using the 'utm_source' parameter Reflected XSS vulnerabilities arise when the application accepts a malicious input script from a user and then it is executed in the victim's...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Reflected xss in https://sh.reddit.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Reflected cross-site scripting (or XSS) arises when an application receives data in an HTTP request and includes that data within the immediate response in an unsafe way.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
