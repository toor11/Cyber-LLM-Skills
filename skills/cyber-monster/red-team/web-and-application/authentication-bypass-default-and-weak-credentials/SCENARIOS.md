# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`authentication-bypass-default-and-weak-credentials`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: default credentials at https://52.42.105.71/

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: hi team i able to login in one of your servers by default credentials Steps to reproduce: 1.go to link : https://52.42.105.71/ 1.enter this credentials password=admin username=admin PoC {F2703747} {F2703748} How to remediate the vulnerability Change the password of the...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Remote code execution via crafted pentaho report uploaded using default credentials for pentaho business

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Good day, While I do recon for mtn.ci domain I found Pentaho business server at https://sm.mtn.ci:8888/pentaho with default credentials admin/password ,then I figured that I can upload prpt reports to server which could use some beanshell,js and java to achieve RCE...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Weak password policy leading to exposure of administrator account access

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, The login endpoint https://mysmartplans.gsa.gov/Marathon/Default.aspx is having weak password policy. During the recon, I came across a mysmartplans overview document http://www.accentimaging.com/accent/pdfs/Accent%20MySmartPlans.pdf .
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Access to Splunk at https://apt.ec2.shopify.com:8089

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description: Default Splunk admin credentials were found at https://apt.ec2.shopify.com:8089 **Default credentials** login:admin password:changeme *See pic 1 as POC* Resolution: Change credentials *Please let me know if you need some extra information.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Brute Force - CheatSheet

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Brute Force - CheatSheet Default Credentials **Search in google** for default credentials of the technology that is being used, or **try these links**: - **https://github.com/ihebski/DefaultCreds-cheat-sheet** - **http://www.phenoelit.org/dpl/dpl.html** -...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: Discover Content and use Default Credentials .

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Discover Content and use Default Credentials . Web Exploitation . Day 3, Advent of Cyber 3 (2021) . TryHackMe Walkthrough Use your investigatory skills and techniques to discover un-listed content, and attempt some common authentication using the clues found.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 7: HackTheBox : Broker

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** HackTheBox : Broker This box was part of TJ Null’s NetSecFocus Trophy Room for OSCP-like boxes. Box Summary * Default Credentials: The box featured a service (Apache ActiveMQ) with default admin credentials. * Initial Access: Involved exploiting a known vulnerability (CVE-2023-46604) in Apache ActiveMQ.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Ethical Hacking Lessons — Arctic Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Arctic Writeup This write-up is for the hackthebox Arctic machine. This box highlights the weaknesses associated with use of weak password techniques that adversaries can exploit and gain full control of a machine. Its a windows machine with an IP address of 10.10.10.11. The radar graph shows presence of CVEs.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.
