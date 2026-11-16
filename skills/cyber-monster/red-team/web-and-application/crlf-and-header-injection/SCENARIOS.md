# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`crlf-and-header-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: CRLF injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello twiiter security team, on the domain ads.twitter.com http response splitting is vulnerability. PoC: https://ads.twitter.com/subscriptions/mobile/landing?ref=gl-tw-tw-promote-mode?t=%0d%0atest:tested Impact an attacker can set new header
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: HTTP Response Splitting (CRLF injection) in report_story

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I would like to report a HTTP Response Splitting vulnerability in https://twitter.com/i/safety/report_story that allows attackers to inject arbitrary headers and contents in the response.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Security bug https://bugzilla.mozilla.org/oauth/authorize - CRLF Header injection via "redirect_uri" para

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: CRLF / HTTP Header Injection. Allows you to set any headers/etc (Set-Cookie...) Page: https://bugzilla.mozilla.org/oauth/authorize Parameter: redirect_uri Steps To Reproduce: PoC - does not require authorization: 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Host Header Injection - internal.qa.delivery.indrive.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: CRLF injection on www.starbucks.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The vulnerability allows setting arbitrary headers, and also enables response splitting which can then be exploited further. POC: curl -i 'https://www.starbucks.com/email-prospecttg9wh%0d%0aset-cookie:foo%0d%0a%0d%0a4t6uf?requesturl=/responsibility/global-report/policies' -d...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: HTTP Response Splitting (CRLF injection) due to headers overflow

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I would like to report another HTTP Response Splitting vulnerability caused by header fields "overflow" that allows attackers to inject arbitrary headers in the response. Note that this issue is similar to #52042 but the root cause is different.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Unvalidated redirect on team.badoo.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Domain affected: https://team.badoo.com/ (corp.badoo.com) PoC (Tested on Firefox): https://team.badoo.com/%0d%0adata:text/html;text,%3Csvg%2fonload%3Dprompt%281%29%3E {F129735} Describe: team.badoo.com may vulnerable to CRLF injection, when we inject %0d%0a into url, the...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Host header injection that bypassed protection and allowed accessing multiple subdomains

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** > NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty, so be sure to take your time filling out the report!...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
