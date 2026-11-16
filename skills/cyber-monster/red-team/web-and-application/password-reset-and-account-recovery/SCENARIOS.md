# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`password-reset-and-account-recovery`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Reset password link sent over unsecured http protocol

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: After creating the workspace, if victim clicks on forgot password then reset password link has been generated and sent over mail and that password link is unsecured http protocol. Steps To Reproduce: 1. Signup to a workspace 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Ability To Delete User(s) Account Without User Interaction

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Gitlab allows its user to exercise their GDPR rights (Right to Access/Delete) user data by sending an email to gdpr-request@gitlab.com however gitlab team doesn't ask for security question(i.e Date Of Birth) before deleting the user account moreover doesn't authenticate...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Account recovery text message is sending a wrong domain to users.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hey, I hope you're fine. :) **Summary:** When users setup Account recovery at Authentication section Hackerone sends them text message to their updated phone number with a wrong domain link.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Broken Authentication - Security token gets captured via man in the middle attack

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Product / URL** 'http://en.instagram-brand.com/register/reset/?email=' **Description and Impact** The password reset links issues by Instagram Brand gets delivered to users inbox with a http scheme and NOT https scheme.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Exposure of account recovery hint by querying by user email

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hey all! Hope everything is good! While testing I noticed that I can issue queries to https://api.accounts.firefox.com/v1/recoveryKey/hint?email=email-to@attack.com to get a specific user Account Recovery Keys hint.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Email enumeration at SignUp page

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi. There's bad security practise at https://trade.go.exchange/en/auth/sign-up against User enumeration. Description: At the signup page here https://trade.go.exchange/en/auth/sign-up , when you enter an existing user's mail , a msg box says "Email is invalid." F546294 The...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: account takeover through password reset in url https://reklama.tochka.com/

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Steps to reproduce 1- Create an account 2- visit this url https://reklama.tochka.com/mainpage1/recover/ 2- Enter your email and intercept the response to the request that recovers your password you will notice that it looks like this HTTP/1.1 200 OK Server: nginx Date: Sun, 24...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Password Reset link hijacking via Host Header Poisoning

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary Concrete5 uses the 'Host' header when sending out password reset links. This allows an attacker to insert a malicious host header, leading to password reset link / token leakage.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
