# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssrf-blind-ssrf`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Unauthenticated blind SSRF in OAuth Jira authorization controller

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The 'Oauth::Jira::AuthorizationsController#access_token' endpoint is vulnerable to a blind SSRF vulnerability. The vulnerability allows an attacker to make arbitrary HTTP/HTTPS requests inside a GitLab instance's network.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Blind SSRF on errors.hackerone.net due to Sentry misconfiguration

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** When setting up Sentry you should turn off "source code scrapping". If it is turned on, then server that has Sentry on it will make blind get requests everywhere controlled from outside via error reporting. **Description:** Hello Hackerone team.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Blind SSRF on https://my.exnessaffiliates.com/ allows for internal network enumeration

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi Hope you're well I have found a Blind SSRF vulnerability, in an endpoint on exnessaffiliates.com endpoint, which would allow for Internal network enumeration.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Blind SSRF in emblem editor (2)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, As per your recommendation in #233301, I'm submitting a PoC for another blind SSRF in the emblem editor. To oversight here is allowing absolute 'url()' values for the 'fill' attribute: '<path fill="url(https://requestb.in/15rxmgv1#test)" stroke="#a1a1a1" ...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Blind SSRF on debug.nordvpn.com due to misconfigured sentry instance

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: The debug subdomain uses Sentry for application monitoring and error tracking. This software comes with a feature (known as source code scraping ) turned on by default which makes it is possible to make blind get requests from the server on which it is running.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Blind SSRF on https://labs.data.gov/dashboard/Campaign/json_status/ Endpoint

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Due to improper routes handling multiple malicious actions are possible. Attacker is able to call Class/Function/Param1/Param2 directly from source code. this may lead to call function that should be not accessible from GUI.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Blind SSRF at https://chaturbate.com/notifications/update_push/

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** In the application at https://chaturbate.com/notifications/update_push/ there is a functionality to subscribe any cam model which will trigger the provided request.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Blind SSRF at packagist.maximum.nl

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello Team, I found a subdomain vulnerable to header blind SSRF: packagist.maximum.nl Steps to Reproduce 1 - Go to https://packagist.maximum.nl/ and intercept it.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
