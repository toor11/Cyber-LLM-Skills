# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`subdomain-takeover`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Report Template: Subdomain Takeover

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** An attacker can serve malicious content on a legitimate organizational subdomain, perform credible phishing and potentially steal cookies if scope is broad.
- **Actionable Takeaway:** 1. Remove obsolete DNS records 2. Implement automated subdomain monitoring 3. Verify CNAMEs before removing external services 4. Restrict cookie scope to main domain

## Case 2: Subdomain takeover of datacafe-cert.starbucks.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** The subdomain datacafe-cert.starbucks.com had an CNAME record pointing to an unclaimed Azure webservice. This is a high severity security issue because an attacker can register the subdomain on Azure and therefore can own the subdomain datacafe-cert.starbucks.com.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Subdomain takeover of storybook.lystit.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: The subdomain storybook.lystit.com had an CNAME record pointing to an unclaimed S3 bucket. This is a high severity security issue because an attacker can register the bucket on AWS and therefore can serve her own content on the subdomain.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Hacker.One Subdomain Takeover

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello HackerOne Sec Team, Description : > This report is about domain takeover of __hacker.one__ via __instapage 0day__ issue which i just found . Step To Verify : + Visit : https://www.hacker.one + You will see some html updated by me.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Subdomain takeover at info.hacker.one

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** Hi team,i've been able to takeover subdomain at __info.hacker.one__, the CNAME entry in the subdomain is pointing to an external page service (app.unbounce.com).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Subdomain Takeover Via Insecure CloudFront Distribution cdn.grab.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Good day, I truly hope it treats you awesomely on your side of the screen :) I have found that your website cdn.grab.com is pointed via a cname to a cloudfront instance cdn.grab.com => *.cloudfront.net This was not registered on Amazon Aws Cloudfront.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Subdomain takeover of d02-1-ag.productioncontroller.starbucks.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** I was able to claim the subdomain: d02-1-ag.productioncontroller.starbucks.com using Azure Cloud Service **Platform(s) Affected:** Subdomain Azure Cloud Service Steps To Reproduce: 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Subdomain takeover on http://fastly.sc-cdn.net/

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hey team, I've found a snapchat cdn domain here which had a test instance of fastly setup but did not remove the dns record when the service was cancelled. This allowed me to create a Fastly instance to take it over.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
