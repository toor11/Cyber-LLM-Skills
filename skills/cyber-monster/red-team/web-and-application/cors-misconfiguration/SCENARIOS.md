# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cors-misconfiguration`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: [www.zomato.com] CORS Misconfiguration, could lead to disclosure of sensitive information

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Cross Origin Resource Sharing Misconfiguration / Lead to sensitive information. Description: An HTML5 cross-origin resource sharing (CORS) policy controls whether and how content running on other domains can perform two-way interaction with the domain that publishes the...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Bypassing CORS Misconfiguration Leads to Sensitive Exposure

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Hi!** Security Team @deptofdefense, It's possible to get information about the users registered (such as: id, name, login name, etc.) without authentication in Wordpress via API on *. ███████.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Local files reading using 'link[rel="import"]'

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: HTML file could import another file using ''. Brave returns 'Access-Control-Allow-Origin: *' response header for local HTML files. That leads to local files reading. > This vulnerability makes #369218 critical.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: CORS misconfiguration which leads to the disclosure of certain data concerning the user.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** INTRODUCTION _I used an account to search for this vulnerability:_ id: 5407773 email: adam-bugbounty@anosimple.com _IP used:_ __2a01:e34:ec2a:9240:7d25:26c3:1449:bfe7__ _endpoint URL:_ https://www.semrush.com/content-paywall/api/accesslevel _Summary:_ CORS policy too permissive.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: subdomain takeover at news-static.semrush.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** The subdomain news-static.semrush.com can be taken over by attackers and abuse it for further attacks (Phishing, XSS Cross origin, malware, etc..).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Site-wide CSRF on Safari due to CORS misconfiguration (not localhost)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description Hello there, on 'new.cs.money' or 'cs.money', there is anti-CSRF mechanism, which is 'Referer' header check. However, I discovered that regex logic for checking 'Referer' header is flawed. I found that adding '{' or '}' at the end of the domain pass the validation.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: CORS - Misconfigurations & Bypass

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-942`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # CORS - Misconfigurations & Bypass ## What is CORS? Cross-Origin Resource Sharing (CORS) standard **enables servers to define who can access their assets** and **which HTTP request methods are permitted** from external sources. A **same-origin** policy mandates that a **server r
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: CrossFitTwo

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-942`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Much like CrossFit, CrossFitTwo was just a monster of a box. The centerpiece is a crazy cross-site scripting attack through a password reset interface using DNS to redirect the admin to a site I control to then have them register an account for me. I'll then hijack some socket.io
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
