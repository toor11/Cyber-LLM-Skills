# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`enterprise-appliance-n-day-vpn-remote-access`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Report Template: Authentication Bypass

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** An unauthenticated attacker can access administrative functionality or protected data, completely compromising application security.
- **Actionable Takeaway:** 1. Implement centralized authentication verification 2. Use authentication middleware on all protected routes 3. Audit code for alternative access paths 4.

## Case 2: Subdomain Takeover to Authentication bypass

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnerability Type: ----------- Subdomain Takeover Description: ----------- Due to unclaimed or expired Hubspot instance an attacker is able to claim and serve content from 'devrel.roblox.com' and perform different kind of attacks which i shared in impact section.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: OneLogin authentication bypass on WordPress sites via XMLRPC

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** When a user logs on one of your WordPress sites via OneLogin, the authentication plugin creates a new entry in the WordPress user database with the default password '@@@nopass@@@'.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Admin Authentication Bypass Lead to Admin Account Takeover

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello Team I found that i can bypass the login page of the Admin account by intercepting the respone of the login request of connectnb.ups.com subdomain and change status from false to true Steps To Reproduce: 1. Open https://connectnb.ups.com/Layout/login 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: OneLogin authentication bypass on WordPress sites

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** First, I'm sorry about reporting another WordPress bug (my intention was just to check if WP-OneLogin stores any sensitive info that could be used to attack OneLogin on your other websites).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Two-factor authentication bypass on Grab Android App

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description I found the endpoint using android app 'https://p.grabtaxi.com/api/passenger/v2/profiles/edit' which allow me to bypass 2FA (sms code) due to lack of rate limiting\code expiration after unsuccessful attempts.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Authentication bypass on JetPack SSO manager - Allows to access the administration panel of wordpress wit

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello team, Summary: The JetPack SSO manager is plugin that allows any user to log into their wordpress using the same log-in credentials you use for WordPress.com, then they’ll now be able to register for and sign in to self-hosted WordPress.org sites quickly, example : User...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Authentication Bypass - Chaining two vulnerabilities leads to account takeover at en.instagram-brand.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Product / URL** https://en.instagram-brand.com/wp-json/brc/v1/login/ **Description and Impact** An attacker can perform account takeover by leveraging following two vulnerabilities: Auth Bypass = Username Enumeration + Login Brute Force A.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
