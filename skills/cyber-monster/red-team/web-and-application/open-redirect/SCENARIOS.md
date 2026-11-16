# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`open-redirect`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Report Template: Open Redirect

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** An attacker can redirect users to a credible phishing site, steal credentials or chain with OAuth vulnerabilities for token theft.
- **Actionable Takeaway:** 1. Implement allowlist of authorized redirect domains 2. Use mapped identifiers instead of direct URLs 3. Warn user before external redirect 4. Validate URL starts with application domain

## Case 2: Remote Code Execution in Slack desktop apps + bonus

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary With any in-app redirect - logic/open redirect, HTML or javascript injection it's possible to execute arbitrary code within Slack desktop apps.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: [cs.money] Open Redirect Leads to Account Takeover

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: I found an open redirect on 'https://cs.money' domain, using this payload 'https://cs.money///google.com' we can redirect into any domain that we want, you can see the request and response from this image below : ███ Steps To Reproduce: The final payload is having an...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: XSS and Open Redirect on MoPub Login

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** I found open redirect at the MoPub login page, https://app.mopub.com/login?next=https://google.com. It also allows javascript URIs, leading to XSS. **Description:** You can modify the "next" URL parameter to redirect to any website upon logging in on MoPub.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Open redirect due to scanning QR code via brave browser

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** > NOTE! Thanks for submitting a report! Please fill all sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to verify and then potentially issue a bounty.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Open URL Redirection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Open URL Redirect Steps To Reproduce: 1) Go to the following link & Register for new account https://unikrn.com/██████ 2) After registering It will redirect to example.com Reference: https://www.owasp.org/index.php/Unvalidated_Redirects_and_Forwards_Cheat_Sheet Impact The...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Safe Redirect Bypass

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello Team, **Summary:** The url below bypasses the safe redirect and redirects directly to the malicious website. 'http://evil.org/%00' The reason for this may be the fix in the report #921286.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Twitter lite(Android): Vulnerable to local file steal, Javascript injection, Open redirect

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** com.twitter.android.lite.TwitterLiteActivity is set to exported and doesn't validate data pass to intent due to which this activity vulnerable to steal users local files, javascript injection and open redirect.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
