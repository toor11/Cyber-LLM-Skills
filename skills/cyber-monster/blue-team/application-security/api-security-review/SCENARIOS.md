# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`api-security-review`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: No Rate Limit On Forgot Password Page Of NordVPN

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Introduction A little bit about Rate Limit: A rate limiting algorithm is used to check if the user session (or IP-address) has to be limited based on the information in the session cache.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: PIN 📌 BYPASS 🥷

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: 983980808 IOS App has improper rate limit. When we try to brute force the PIN, we are rate limited for 5 minutes after 5 or 6 attempt. In my testing I found that it was checking the device's local date / time so by changing it we can brute force the PIN.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Bypass rate limiting on /users/password (possibly site-wide rate limit bypass?)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi there, I noticed when we hit the /users_sign_in endpoint too many times it will give us ' HTTP/1.1 429 Too Many Requests Date: Mon, 19 Sep 2016 01:52:19 GMT Content-Type: text/plain ' However, this can be "reset" although I struggle to get it to work EVERYTIME on...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: No rate limiting for confirmation email lead to huge Mass mailings

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Issue Description** No rate limit means their is no mechanism to protect against the requests you made in a short frame of time. If the repetition doesn't give any error after 50, 100, 1000 repetitions then their will be no rate limit set.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Basic auth header on WebDAV requests is not bruteforce protected

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi Team, I hope you are doing well. Vulnerability Name :- Basic Authentication Bypass due to Lack of Rate Limit Vulnerable URL :- https://efss.qloud.my/remote.php/dav/calendars/ha.ckitbharat3@gmail.com/app-generated--deck--board-5269/ Steps to Reproduce :- 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: [intensedebate.com] No Rate Limit On The report Functionality Lead To Delete Any Comment When it is enabl

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello Summary: I have found a no rate limit issue on the report functionality. When you enabled the report functionality on your site, you can set a number of reports before deleting the comment reported.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Vulnerability Report: NO RATE LIMIT Password RESET

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** / **CAUTION** : External email. Do not click links or open attachments unless you recognize the sender and know the content is safe. / * * * Vulnerability Description: There is no limit for number of password reset that are being sent to the user This may lead for attacker to...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Missing rate limit for current password field (Password Change) Account Takeover

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnerability: Missing Rate Limit for Current Password field (Password Change) Account Takeover Steps to reproduce the bug: 1)Go to Profile > Password. Enter any (wrong password) In current password filed. 2)Now enter the new password and Turn the Intercept ON.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
