# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`mobile-and-hybrid-web-api-abuse`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: No Rate Limit On Forgot Password Page Of NordVPN

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Introduction A little bit about Rate Limit: A rate limiting algorithm is used to check if the user session (or IP-address) has to be limited based on the information in the session cache.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: No rate limiting for confirmation email lead to huge Mass mailings

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Issue Description** No rate limit means their is no mechanism to protect against the requests you made in a short frame of time. If the repetition doesn't give any error after 50, 100, 1000 repetitions then their will be no rate limit set.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: [intensedebate.com] No Rate Limit On The report Functionality Lead To Delete Any Comment When it is enabl

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello Summary: I have found a no rate limit issue on the report functionality. When you enabled the report functionality on your site, you can set a number of reports before deleting the comment reported.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: [www.stripo.email] There is no rate limit for contact-us endpoints

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary The speed limit for the *https://stripo.email/es/contact-us* endpoint has not been implemented. Steps To Reproduce 1. Go to the *https://stripo.email/es/contact-us* 2. Turn on blocking and fill out the contact form 3. Send request to Intruder. 4.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: No Rate Limit when accessing "Password protection" enabled surveys leads to bypassing passwords via "pd-p

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi team, If you write the right password on any password protected survey, you will see this request : {F878934} This request is protected with rate limit, that's great. But if you look to response, you will see a cookie.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: No rate limit on app.crowdsignal.com (Finish quiz)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello team [https://hackerone.com/reports/488923 ]--> vulnerability resolved maybe you can compare the report to start this, but this vulnerability has been closed.this is a separate no-rate limit error.this is not a duplicate bug.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: No Rate Limit on redditgifts gift when Adding Comment

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi team, I hope this report should not be closed as INFORMATIVE **Summary:** The add comment endpoint was improperly rate-limited so the potential attacker could post a large number of comments, overloading the server .
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: No Rate Limit On Reset Password

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: A rate limiting algorithm is used to check if the user session (or IP address) has to be limited based on the information in the session cache.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
