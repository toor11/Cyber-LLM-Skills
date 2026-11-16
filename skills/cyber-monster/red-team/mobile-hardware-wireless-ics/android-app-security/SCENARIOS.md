# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`android-app-security`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Able to steal bearer token from deep link

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Pre-requisities Prior to exploitation you would be required to know the "account id" of the user that you are attacking. Whilst this makes it difficult to attack an application in a generic way - the account is not secret information as it is included in any links to a user's...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: CSRF vulnerability in Nextcloud Desktop Client 3.6.1 on Windows when clicking malicious link

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary It is possible to make a user send any POST request with an arbitrary body given they click on a malicious deep link. (e.g. in an email, chat link, etc) This vulnerability was introduced in an attempt to fix #1720043.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Android Applications Basics

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Android Applications Basics Android Security Model **There are two layers:** - The **OS**, which keeps installed applications isolated from one another. - The **application itself**, which allows developers to **expose certain functionalities** and configures application capabilities.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 4: Mobile Hacking Lab Guess Me

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Mobile Hacking Lab Guess Me Introduction Welcome to the “Guess Me” Deep Link Exploitation Challenge! Immerse yourself in the world of cybersecurity with this hands-on lab.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 5: Android Pentesting-Bypassing Root Detection

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-926`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # Android Pentesting-Bypassing Root Detection For the demonstration of bypassing root detection I will be using a vulnerable apk known as insecurebankv2 which is quite showcased in talks and presentations however there are other vulnerable applications that you can try to practic
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: HTB: BigBang

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-926`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** BigBang has a WordPress site with the BuddyForms plugin. I'll find a 2023 CVE that involves uploading a PHAR / GIF polyglot. It doesn't work, but it does show how to read GIFs, which I'll turn to the local system. Then using a PHP-filter-based tool I'll abuse this to read arbitra
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: HTB: RouterSpace

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-926`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** RouterSpace was all about dynamic analysis of an Android application. Unfortunately, it was a bit tricky to get setup and working. I’ll use a system-wide proxy on the virtualized Android device to route traffic through Burp, identifying the API endpoint and finding a command inje
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: HTB: Cypher

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-926`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Cypher starts with a website advertising a graph database. I’ll use cypher injection to bypass the login and get into the site. I’ll find a JAR file for a Neo4J extension and reverse engineer it to find command injection in a custom cypher method. I’ll abuse that to get a shell o
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
