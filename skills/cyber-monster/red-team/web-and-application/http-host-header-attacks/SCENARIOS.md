# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`http-host-header-attacks`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Account Takeover in Periscope TV

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** When you login periscope.tv using twitter, and change the host header from 'www.periscope.tv' to 'attacker.com/www.periscope.tv', the oauth redirect destination will be 'attacker.com/www.periscope.tv', thus allowing attacker to send the oauth authorize link to...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Header modification results in disclosure of Slack infra metadata to unauthorized parties

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I found *files.slack.com* domain will honor the **X-Forwarded-Host** header, instead of host header. Although file.slack.com has host validation to return 500 Internal server error when host is not files.slack.com, I can bypass the validation by appending @ at the end of host...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Reverse Proxy misroute leading to steal X-Shopify-Access-Token header

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello Shopify team! I found out that on /admin/api/graphql endpoint server fetches content of Host header value (${HTTP_Host} + /admin/api/graphql). If my own host was sent to server, request comes from ██████████or ██████████ (your google cloud cluster).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: https://themes.shopify.com::: Host header web cache poisoning lead to DoS

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi there, I just found the website: https://themes.shopify.com is infected with "Web cache poisoning" via HOST header lead to Denial of Services Abuse this bug, Attacker can: Poison your cache with HTTP header Host header with arbitrary PORT which is not opened.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Password Reset Link not expiring after changing the email Leads To Account Takeover

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnerability: Password Reset Link not expiring after changing the email Proof Of Concept: 1.Send the password reset link to your email. 2.Don't open the password link just copy it and paste into any editor. 3.Open your account. 4.Go to your account settings.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Password Reset link hijacking via Host Header Poisoning

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary Concrete5 uses the 'Host' header when sending out password reset links. This allows an attacker to insert a malicious host header, leading to password reset link / token leakage.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Host Header Injection leads to Open Redirect and Content Spoofing or Text Injection.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: 1.) Open Redirection The https://dashboard.omise.co/test/dashboard website is vulnerable to an Open Redirection flaw if the server receives a crafted X-Forwarded-Host header.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Host Header Injection - internal.qa.delivery.indrive.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** HTTP Host header attacks exploit vulnerable websites that handle the value of the Host header in an unsafe way. If the server implicitly trusts the Host header, and fails to validate or escape it properly, an attacker may be able to use this input to inject harmful payloads that...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
