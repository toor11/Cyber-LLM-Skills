# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`csv-formula-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: CSV Injection at https://assets-paris-demo.codefi.network/

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi consensys Security Team. I have found CSV Injection when generate report at https://assets-paris-demo.codefi.network/ CSV Injection, also known as Formula Injection, occurs when websites embed untrusted input inside CSV files.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: CSV Injection at Camptix Event Ticketing

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, As you mentioned the scope of vulnerability as >Any plugin listed on my WordPress.org profile. I am reporting this issue. I have seen from your WordPress.org profile the second plugin listed is **Camptix Event Ticketing** So I looked at the source code of the plugin...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Formula/CSV/Doc/LaTeX/GhostScript Injection

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Formula/CSV/Doc/LaTeX/GhostScript Injection {{#include ../banners/hacktricks-training.md}} Formula Injection Info If your **input** is being **reflected** inside **CSV file**s (or any other file that is probably going to be opened by **Excel**), you maybe able to put Excel **formulas** that will be...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: The Absurdly Underestimated Dangers of CSV Injection

- **Provenance:** Source: `CYBER_CPT/L5/awesome_web_security`
- **Context / Surface:** High-depth analysis (awesome_web_security, edu=4)
- **Root Cause / Analysis:** The Absurdly Underestimated Dangers of CSV Injection 7 October, 2017 I’ve been doing the local usergroup circuit with this lately and have been asked to write it up. In some ways this is old news, but in other ways…well, I think few realize how absolutely devastating and omnipresent this vulnerability can be.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: The Absurdly Underestimated Dangers of CSV Injection

- **Provenance:** Source: `CYBER_CPT/awesome_web_security` | CWE: `CWE-1236`
- **Context / Surface:** Source: awesome_web_security (en)
- **Root Cause / Analysis:** # The Absurdly Underestimated Dangers of CSV Injection 7 October, 2017 I’ve been doing the local usergroup circuit with this lately and have been asked to write it up. In some ways this is old news, but in other ways…well, I think few realize how absolutely devastating and omnipr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Wordpress Plugin Form Maker version 1.12.20 vulnerable to to Formula Injection (CSV Injection)

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-1236`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # WordPress Plugin Form Maker 1.12.20 - CSV Injection / / / / / --- / --- / --- / / EKU-ID: 48501 / CVE: [CVE-2018-10504] (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-CVE-2018-10504) / OSVDB-ID: / / Author: Sairam Jetty / Published: 2018-04-30 / Verified: ![Verified] (/images
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: osTicket-v1.12 Formula Injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-1236`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # osTicket 1.12 - Formula Injection EKU-ID: 51325 CVE: CVE-2019-14749 Published: 2019-08-12 # Exploit Title: osTicket-v1.12 Formula Injection # Vendor Homepage: https://osticket.com/ # Software Link: https://osticket.com/download/ # Exploit Author: Aishwarya Iyer # Contact: https
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: WordPress Plugin TablePress 1.14 - CSV Injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-1236`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # WordPress Plugin TablePress 1.14 - CSV Injection EKU-ID: 54209 CVE: OSVDB-ID: Author: Nikhil Kapoor Published: 2021-09-08 Verified: Not Verified Download: # Exploit Title: WordPress Plugin TablePress 1.14 - CSV Injection # Date: 07/09/2021 # Exploit Author: Nikhil Kapoor # Vend
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
