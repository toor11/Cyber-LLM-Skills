# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-cache-poisoning-and-deception`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Denial of service to WP-JSON API by cache poisoning the CORS allow origin header

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** The WP-JSON implementation on some wordpress.com websites I've tested is vulnerable to denial of service where by an attacker can provide an arbitrary 'Origin' header in the request, which is then echoed back in the response via the 'Access-Control-Allow-Origin' header, which is...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Denial of service via cache poisoning

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** An attacker can persistently block access to any/all redirects on www.hackerone.com by using cache poisoning with the X-Forwarded-Port or X-Forwarded-Host headers to redirect users to an invalid port.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Static files on HackerOne.com can be made inaccessible through Cache Poisoning attack

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi, The host hackerone.com uses cloudlfare to cache static files. The header x-forwarded-scheme can be used to cause a redirect loop, which will be cached by cloudflare.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: XSS and cache poisoning via upload.twitter.com on ton.twitter.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I would like to report an issue where attackers can bypass the upload restriction on upload.twitter.com to cause XSS on ton.twitter.com and cache poisoning.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Cache Poisoning allows redirection on JS files

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I found the following Cache Poisoning vulnerability: 1. Send the following request: ( this will poison '/test.js' into redirecting to 'https://youst.in/test.js') http GET /test.js?cb=1 HTTP/2 Host: design.glassdoor.com Sec-Ch-Ua: "Google Chrome";v="107", "Chromium";v="107",...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Cache Deception Allows Account Takeover

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: I'm able to extract user's session (HASESSIONV3) as it is disclosed in a cacheable page, allowing me to access the 'ha.crumb' token located in '/traveler/profile/edit' http GET /traveler/profile/edit HTTP/2 Host: www.abritel.fr Cookie: HASESSIONV3=...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Cache Poisoning DoS on downloads.exodus.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hello, The subdomain downloads.exodus.com hosts all files meant to be downloaded by exodus users. A few of the file I found are: https://downloads.exodus.com/releases/exodus-linux-x64-21.4.9.zip https://downloads.exodus.com/releases/hashes-exodus-21.2.12.txt...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Cache Poisoning Allows Stored XSS Via hav Cookie Parameter (To Account Takeover)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Report #1698316 was closed as resolved You told me that the stored XSS was going to be resolved since "As this relies on the same root cause, we will be closing it as duplicate", but no abritel.fr has a strong WAF, however the server hides double quotes, allowing to...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
