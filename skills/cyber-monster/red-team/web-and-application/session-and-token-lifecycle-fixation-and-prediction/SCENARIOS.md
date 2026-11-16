# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`session-and-token-lifecycle-fixation-and-prediction`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: H1514 Session Fixation on multiple shopify-built apps on *.shopifycloud.com and *.shopifyapps.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi team!, I'm reporting a Session Fixation issue on multiple shopify-built apps hosted on *.shopifycloud.com and *.shopifyapps.com. Normally Session Fixation is boring but I discovered a way to simply use by-design XSS to authenticate as a user on those affected apps.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: CVE-2022-27779: cookie for trailing dot TLD

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2022-27779`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Published Advisory: https://curl.se/docs/CVE-2022-27779.html Original Report: https://hackerone.com/reports/1553301 Impact This can allow arbitrary sites to set cookies that then would get sent to a different and unrelated site or domain. (ie. conduct session fixation attacks.)
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: CVE-2023-40273: Session fixation in Apache Airflow web interface

- **Provenance:** Source: `hackerone_disclosed_reports` | CVE: `CVE-2023-40273`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** When I reset the password of the test user through the button Reset Password, I hope that the person who previously had the password of the test user will lose the corresponding authority. However, if others have logged in to the test user before, they can still use the account.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Session fixation on public talk links

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** 1. userA shares a talk room and protects it with a password 2. userB opens links but doesn't enter the password yet 3. Attacker steals the cookies from userB 4. userB logs in 5.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Session fixation in password protected public download.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Public downloads protected with a password are vulnerable to a session fixation attack. This finding was discovered during a penetration test of NextCloud version 10.0.2.7.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: AVideo has Session Fixation via GET PHPSESSID Parameter With Disabled Login Session Regeneration

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-384`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ## Summary AVideo's '_session_start()' function accepts arbitrary session IDs via the 'PHPSESSID' GET parameter and sets them as the active PHP session. A session regeneration bypass exists for specific blacklisted endpoints when the request originates from the same domain. Combi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Session fixation

- **Provenance:** Source: `CYBER_CPT/pentest_book` | CWE: `CWE-384`
- **Context / Surface:** Source: pentest_book (en)
- **Root Cause / Analysis:** Session fixation attacks force a user to use a session ID known to the attacker, enabling account takeover after the victim authenticates. # How It Works 1. Attacker obtains a valid session ID from the target site 2. Attacker tricks victim into using that session ID 3. Victim aut
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: NEC Univerge Sv9100 WebPro - 6.00 - Predictable Session ID / Clear Text Password Storage

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-384`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # NEC Univerge Sv9100 WebPro - 6.00 - Predictable Session ID / Clear Text Password Storage / EKU-ID: 49871 / CVE: CVE-2018-11742; CVE-2018-11741 / OSVDB-ID: / / --- / --- / --- / / Author: hyp3rlinx / Published: 2018-12-04 / Verified: Not Verified / 'python ' [+] Credits: hyp
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
