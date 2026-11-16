# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`file-upload-and-webshell`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Webshell via File Upload on ecjobs.starbucks.com.cn

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** OS Command Injection which can let the attacker who get more important information of the server,such as disclosures internal source code of the webapp,database data and invade the internal network.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Unrestricted file upload leads to Stored XSS

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary i found that i can upload png file with JavaScript code and execute it in wiki page. Steps to reproduce (Step-by-step guide to reproduce the issue, including:) 1-login to gitlab account 2-open your project 3-open Wiki page. 4-Click "New page" button.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: CVE-2021-40870 on [52.204.160.31]

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2021-40870`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** An issue was discovered in Aviatrix Controller 6.x before 6.5-1804.1922. Unrestricted upload of a file with a dangerous type is possible, which allows an unauthenticated user to execute arbitrary code via directory traversal.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: [www.werkenbijbakertilly.nl] Denial of service due to incorrect server return can result in total denial

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary When sending too much data through file upload, the server returns an invalid 500 status code instead of the speed 429 status code, causing an internal denial of service.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: [Kafka Connect] [JdbcSinkConnector][HttpSinkConnector] RCE by leveraging file upload via SQLite JDBC driv

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: The Aiven JDBC sink includes the SQLite JDBC Driver. This JDBC driver can be used to upload SQLite database files onto the server. The HTTP sink connector allows sending HTTP requests to localhost. There is unprotected Jolokia listening on 'localhost:6725'.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: China - ecjobsdc.starbucks.com.cn html/shtml file upload vulnerability

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** 1, Summary During the test, I found ecjobsdc.starbucks.com.cn this site has an upload vulnerability, you can upload html and shtml format files, so you can read the server's intranet IP, the physical address of the website application and read the website web.config file.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: XSS Stored via Upload avatar PNG [HTML] File in accounts.shopify.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello team, I found unrestricted file upload via avatar in https://accounts.shopify.com/accounts/, and XSS Stored in PNG IDAT chunks using exiftool , >exiftool command exiftool -Comment="\">alert(prompt('XSS BY ZEROX4'))"...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Unrestricted File Upload on reddit.secure.force.com

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2022-30190`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Reddit.secure.force.com is Reddit SalesForce instance. Attacker is able to send attachments of disallowed filetypes to this server. The attacker is able to send malicious documents such as CVE-2022-30190 Follina to the victim.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
