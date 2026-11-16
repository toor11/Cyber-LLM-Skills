# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cross-site-scripting`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Report Template: Cross-Site Scripting (XSS) Stored

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** An attacker can steal session cookies of all users visiting the page, perform actions on their behalf, redirect to a phishing site or modify page content for all visitors.
- **Actionable Takeaway:** 1. Encode all HTML output based on context (HTML entity encoding) 2. Implement strict Content Security Policy 3. Use a framework with auto-escaping (React, Angular, Vue.js) 4.

## Case 2: [accounts.reddit.com] Redirect parameter allows for XSS

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hello team! I was tampering with the dest parameter in accounts.reddit.com and found out it is vulnerable to Cross Site Scripting once the victim performs the log in. Steps To Reproduce: 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Stored XSS in my staff name fired in another your internal panel

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi all, I had lots of tests for bug bounty in my test store "trstore-3.myshopify.com" (created about 4 years ago) and then one of your developers noticed that a stored cross-site scripting payload in my staff name fired in another your internal panel.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: DOM XSS on duckduckgo.com search

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, The is a DOM XSS vulnerability on https://duckduckgo.com search through the norw parameter. PoC URL: https://duckduckgo.com/?q=a&norw="> Screenshot: {F820482} Impact The attacker can execute JS code.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Cross-site Scripting (XSS) on HackerOne careers page

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Dear HackerOne team, **Summary:** I found DOM XSS at endpoint 'https://www.hackerone.com/careers', but can not bypass CSP. It's work on IE and Edge.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: DOM Based XSS in www.hackerone.com via PostMessage

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** The Marketo contact form available on the www.hackerone.com website is affected by a cross-site scripting vulnerability, caused by an insecure 'message' event listener installed on the page.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Reflected Cross site Scripting (XSS) on www.starbucks.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** Reflected Cross site Scripting (XSS) on https://www.starbucks.com/account/signin?ReturnUrl **Description:** The attacker can execute javascript on the victims account just after the authentication process.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: XSS in gist integration

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** 1. Create a gist called: "> 2. have gist integration enabled and put a link in a slack chat 3. Visit the 'raw' or 'new window' pages for this gist, for example: https://outpost.slack.com/files/zemnmez/F029MDY33/___svg_onload_alert_1__
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
