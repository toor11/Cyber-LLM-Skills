# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`csp-and-security-header-bypass`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Stored XSS in Notes (with CSP bypass for gitlab.com)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary I read the issue 345657 which handles the XSS in notes reported in Hackerone report 1398305. This issue fixes the reported XSS but leaves the HTML injection that was also mentioned.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Prototype Pollution leads to XSS on https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** deparam function which parses location.hash in https://s.swiftypecdn.com/install/v2/st.js is vulnerable to prototype pollution. There is a script gadget in the same js file which leads to XSS.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Possible XSS vulnerability without a content security bypass

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi security team members, Hope you are well and doing great :) I found a **Possible XSS vulnerability in https://dashboard.stripe.com but I was not able to bypass a content security policy.** Although, I don't have much knowledge about CSP and its bypasses.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: CSP bypass on PortSwigger.net using Google script resources

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary Hi team! I read this blogpost again after playing with an Angular CSP bypass in this Twitter thread https://twitter.com/sudhanshur705/status/1732760081094091117 I found a way to load arbitrary scripts (escaping the restrictions of Angular) if the page uses nonce-based...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: csp bypass + xss

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, On my previous report (number 126464) I've mentioned that analytics.twitter.com has a CSP bypass which I couldn't exploit that time. Now, I've found a reflected XSS on careers.twitter.com which again I couldn't exploit by itself.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: XSS vulnerability without a content security bypass in a 'CUSTOM' App through Button tag

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi security team members, Hope you are well and doing great :) I found a **Possible XSS vulnerability in 'CUSTOM' App through the Button tag but I was not able to bypass a content security policy.** This report is similar to my previous report(#1804177).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Google Analytics could be used as CSP bypass for data exfiltration on hackerone.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Greetings, I believe I may have found a way to bypass CSP on hackerone.com The issue lies here: img-src 'self' data: www.google-analytics.com As you can imagine, how can image tags be used maliciously here to this safe site? Well, as you know, on google-analytics.com we have the...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Stored XSS in Mermaid when viewing Markdown files

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary GitLab's Mermaid configuration allows an attacker to inject HTML in the rendered Markdown. This can be combined with a CSP bypass using pipeline artifacts to achieve RCE. Steps to reproduce 1. Create a repository on GitLab.com 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
