# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`web-cache-poisoning-and-deception-deception-and-path`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Cache Deception Allows Account Takeover

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: I'm able to extract user's session (HASESSIONV3) as it is disclosed in a cacheable page, allowing me to access the 'ha.crumb' token located in '/traveler/profile/edit' http GET /traveler/profile/edit HTTP/2 Host: www.abritel.fr Cookie: HASESSIONV3=...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: CSRF-tokens on pages without no-cache headers, resulting in ATO when using CloudFlare proxy (Web Cache De

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, I noticed this issue on one of your clients which was using CloudFlare in front of their Discourse. This is not affecting 'try.discourse.org' but the same underlying issue can be seen there as well even though it's not exploitable on that specific domain.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Web cache deception attack on https://open.vanillaforums.com/messages/all

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I have found a Vulnerability in vanilla forums which called Web cache deception attack. Web Cache Deception Attack Websites often tend to use web cache functionality to store files that are often retrieved, to reduce latency from the web server.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: web cache deception in https://tradus.com lead to name/user_id enumeration and other info

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** __summary__ Hi OLX team, i found a web cache deception vulnerability in https://tradus.com. With this vulnerability an attacker can gain access to the name of the victim user, the user_id and other informations.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Web Cache Deception Attack (XSS)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** This XSS does not affect the try.discourse.org, but worked on many other Discourse instances, that i tested. In discussions with the Mozilla team, we came to the conclusion that this is a vulnerability in the Discourse and it needs to be sent through this program.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Shopify.com Web Cache Deception vulnerability leads to personal information and CSRF tokens leakage

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Shopify.com Web Cache Deception Vulnerability **Matteo Golinelli, July 21, 2021**. I am testing websites for possible Web Cache Deception vulnerabilities (you can find more about it here) and I discovered that...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: ChatGPT Account Takeover - Wildcard Web Cache Deception / Harel Security Research

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** Harel Security Research About ChatGPT Account Takeover - Wildcard Web Cache Deception Feb 4, 2024 Intro Here’s how I was able to take over your account in ChatGPT. Last year Nagli discovered a web cache deception vulnerability in ChatGPT.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 8: Web Cache Deception

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-525`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **Web Cache Deception** is an attack that tricks a cache into storing a victim's sensitive, dynamic content by exploiting URL parsing inconsistencies between the cache and the application server. ### How It Works The attacker crafts a URL that the application interprets as a dyna
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
