# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ldap-and-xpath-injection-xpath`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: XPATH injection

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-90`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # XPATH injection ## Basic Syntax An attack technique known as XPath Injection is utilized to take advantage of applications that form XPath (XML Path Language) queries based on user input to query or navigate XML documents. ### Nodes Described Expressions are used to select vari
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: xpath injection

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-90`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # xpath injection ## Detection method To find this vulnerabilities sends the string "d'z'0" to every injection point, and searches the response for XPATH errors ### Basic Payloads ' d'z"0 <!--" ' ##### Regexp for error ' System\.Xml\.XPath\.XPathException/MS\.Internal\.Xml/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: XPath Injection

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-90`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **XPath Injection** is a vulnerability where user input is incorporated into XPath queries without proper sanitization, allowing attackers to manipulate queries to access unauthorized data from XML documents. ### How It Works XPath is a query language for selecting nodes from XML
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: Concrete5 CME v9.1.3 - Xpath injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-90`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Concrete5 CME v9.1.3 - Xpath injection / / / / / --- / --- / --- / / EKU-ID: 55038 / CVE: / OSVDB-ID: / / Author: nu11secur1ty / Published: 2023-03-30 / Verified: ![Not Verified] (/images/cancel.png) / / Download: / / / / / / --- / / Rating☆☆☆☆☆ / [![] (/images/prev.png)] (/local/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: Ametys CMS 3.5.2 - 'lang' XPath Injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-90`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Network Services TryHackme Writeup (SMB,Telnet,FTP) Room link: https://tryhackme.com/room/networkservices Hello and welcome! This room will explore common Network Service vulnerabilities and misconfigurations, but in order to do that, we’ll need to do a few things first! A basi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Blind SQL/XPath injection in OPMANAGER

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-90`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Bandit 19–20 > To gain access to the next level, you should use the setuid binary in the homedirectory. Execute it without arguments to find out how to use it. The password for this level can be found in the usual place (/etc/bandit_pass), after you have used the setuid binary.
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
