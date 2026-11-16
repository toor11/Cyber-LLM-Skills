# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`xml-attacks-xxe-and-xslt`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: XPATH injection

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** XPATH injection Basic Syntax An attack technique known as XPath Injection is utilized to take advantage of applications that form XPath (XML Path Language) queries based on user input to query or navigate XML documents.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: Cold VVars Try Hack Me Write-up

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Cold VVars Try Hack Me Write-up This room was an Easy-Medium room on https://tryhackme.com initial compromise is done via Xpath injection and faulty SMB configuration. Nmap Scan As always first thing to do after the machine boots is to fire up an nmap scan. We can see two interesting ports open 8080 and 8082.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 3: XPATH injection

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-611`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # XPATH injection ## Basic Syntax An attack technique known as XPath Injection is utilized to take advantage of applications that form XPath (XML Path Language) queries based on user input to query or navigate XML documents. ### Nodes Described Expressions are used to select vari
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: xpath injection

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-611`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # xpath injection ## Detection method To find this vulnerabilities sends the string "d'z'0" to every injection point, and searches the response for XPATH errors ### Basic Payloads ' d'z"0 <!--" ' ##### Regexp for error ' System\.Xml\.XPath\.XPathException/MS\.Internal\.Xml/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: XPath Injection

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-611`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **XPath Injection** is a vulnerability where user input is incorporated into XPath queries without proper sanitization, allowing attackers to manipulate queries to access unauthorized data from XML documents. ### How It Works XPath is a query language for selecting nodes from XML
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: Concrete5 CME v9.1.3 - Xpath injection

- **Provenance:** Source: `CYBER_CPT/expku` | CWE: `CWE-611`
- **Context / Surface:** Source: expku (en)
- **Root Cause / Analysis:** # Concrete5 CME v9.1.3 - Xpath injection / / / / / --- / --- / --- / / EKU-ID: 55038 / CVE: / OSVDB-ID: / / Author: nu11secur1ty / Published: 2023-03-30 / Verified: ![Not Verified] (/images/cancel.png) / / Download: / / / / / / --- / / Rating☆☆☆☆☆ / [![] (/images/prev.png)] (/local/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Xml Attacks

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-611`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** ## XML Vulnerabilities XML processing modules may be not secure against maliciously constructed data. An attacker could abuse XML features to carry out denial of service attacks, access logical files, generate network connections to other machines, or circumvent firewalls. The pe
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: XSLT Injection

- **Provenance:** Source: `CYBER_CPT/pentesterlab` | CWE: `CWE-611`
- **Context / Surface:** Source: pentesterlab (en)
- **Root Cause / Analysis:** **XSLT Injection** is a vulnerability where attackers can inject malicious content into XSLT (Extensible Stylesheet Language Transformations) stylesheets, potentially leading to information disclosure, server-side request forgery, or remote code execution. ### How It Works XSLT t
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
