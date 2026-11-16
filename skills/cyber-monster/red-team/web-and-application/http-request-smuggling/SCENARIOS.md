# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`http-request-smuggling`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Stealing Zomato X-Access-Token: in Bulk using HTTP Request Smuggling on api.zomato.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Intro Hi Zomato Security Team! My name is Evan Custodio and this is my first time evaluating your platform. I specialize in looking for server-side vulnerabilities. Recently I've taken a deep look at HTTP Request Smuggling issues.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: HTTP Request Smuggling due to CR-to-Hyphen conversion

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** > NOTE! Thanks for submitting a report! Please replace *all* the [square] sections below with the pertinent details. Remember, the more detail you provide, the easier it is for us to triage and respond quickly, so be sure to take your time filling out the report! **Summary:**...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Possibility of Request smuggling attack

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Request smuggling was possible by throwing an IOException with the upper size limit of the trailer header. Confirmed with tomcat version 9.0.82.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Pause-based desync in Apache HTTPD

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Apache was vulnerable to a pause-based desync. This vulnerability is described in detail in my whitepaper here: https://portswigger.net/research/browser-powered-desync-attacks#pause Impact This enables server-side HTTP Request Smuggling when Apache is deployed as a back-end...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Potential HTTP Request Smuggling in ruby webrick

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** function read_body in file /lib/webrick/httprequest.rb use expression /chunked/io to decide transfer-encoding whether or not. that is not rigorous. When using webrick as a http server, a attacker may use a Transfer-Encoding: AAAchunkedBBB header to fake a legal header.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: CVE-2024-21733 Apache Tomcat HTTP Request Smuggling (Client- Side Desync) (CWE: 444)

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2024-21733`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Apache Tomcat from 8.5.7 through 8.5.63, from 9.0.0-M11 through 9.0.43 are vulnerable to client-side de-sync attacks. Client-side de-sync (CSD) vulnerabilities occur when a web server fails to correctly process the Content-Length of POST requests.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: [crm.unikrn.com] Open Redirect

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi there is an open redirect vulnerable in crm.unikrn.com POC curl http://crm.unikrn.com//example.com/ -L -v Response < HTTP/1.1 302 Moved Temporarily < Date: Thu, 14 Dec 2017 09:06:08 GMT < Transfer-Encoding: chunked < Connection: keep-alive < Cache-Control: private, max-age=0,...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Request Smuggling in Apache Tomcat (Important, CVE-2023-45648)

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2023-45648`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Apache Tomcat supports Trailer Section. However, we found that in version prior than 11.0.0-M11, 10.1.13, 9.0.80, 8.5.93, Apache Tomcat cannot properly parse the trailer section if there's no colon in the trailer header's line.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
