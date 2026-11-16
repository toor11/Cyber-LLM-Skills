# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`android-app-security-static-analysis`](SKILL.md) | Family: **Mobile, Hardware, Wireless and ICS**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTB: BigBang

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-926`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** BigBang has a WordPress site with the BuddyForms plugin. I'll find a 2023 CVE that involves uploading a PHAR / GIF polyglot. It doesn't work, but it does show how to read GIFs, which I'll turn to the local system. Then using a PHP-filter-based tool I'll abuse this to read arbitra
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: HTB: RouterSpace

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-926`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** RouterSpace was all about dynamic analysis of an Android application. Unfortunately, it was a bit tricky to get setup and working. I’ll use a system-wide proxy on the virtualized Android device to route traffic through Burp, identifying the API endpoint and finding a command inje
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: Reversing Native Libraries

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-926`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Reversing Native Libraries **For further information check:** [**https://maddiestone.github.io/AndroidAppRE/reversing_native_libs.html**] (https://maddiestone.github.io/AndroidAppRE/reversing_native_libs.html) Android apps can use native libraries, typically written in C or C++,
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Cypher

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-926`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Cypher starts with a website advertising a graph database. I’ll use cypher injection to bypass the login and get into the site. I’ll find a JAR file for a Neo4J extension and reverse engineer it to find command injection in a custom cypher method. I’ll abuse that to get a shell o
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: OTP Vault

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-926`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Hashes Galore! ![\\"Simon] (\\"https://miro.medium.com/v2/resize:fill:88:88/1*SIYE4zPimOyG3pTXPK1ZjQ.png\\") Simon Moseley · Follow 11 min read · Nov 26, 2022 Listen Share This is the official writeup for the TryHackMe room Hashes Galore. ![\\"\\"] (\\"https://miro.medium.com/v2/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: android

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-926`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # How Capture The Flag Events Can Help You ![\\"BugBase] (\\"https://miro.medium.com/v2/da:true/resize:fill:88:88/0*MDD6YyZepKHOTUdw\\") BugBase - The BugGyaan Blog · Follow 3 min read · Oct 4, 2022 \-- Listen Share # What is CTF for Organizations? A CTF can be viewed as a learnin
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
