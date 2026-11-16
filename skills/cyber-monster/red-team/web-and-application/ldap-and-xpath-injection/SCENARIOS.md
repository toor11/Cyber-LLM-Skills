# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ldap-and-xpath-injection`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: LDAP Injection

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** LDAP Injection LDAP **LDAP Injection** is an attack targeting web applications that construct LDAP statements from user input. It occurs when the application **fails to properly sanitize** input, allowing attackers to **manipulate LDAP statements** through a local proxy, potentially leading to...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 2: XPATH injection

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** XPATH injection Basic Syntax An attack technique known as XPath Injection is utilized to take advantage of applications that form XPath (XML Path Language) queries based on user input to query or navigate XML documents.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 3: Cold VVars Try Hack Me Write-up

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Cold VVars Try Hack Me Write-up This room was an Easy-Medium room on https://tryhackme.com initial compromise is done via Xpath injection and faulty SMB configuration. Nmap Scan As always first thing to do after the machine boots is to fire up an nmap scan. We can see two interesting ports open 8080 and 8082.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 4: TryHackMe — LDAP Injection — Writeup

- **Provenance:** Source: `CYBER_CPT/ctf_search` | CWE: `CWE-90`
- **Context / Surface:** Source: ctf_search (en)
- **Root Cause / Analysis:** # TryHackMe — LDAP Injection — Writeup # Key points: LDAP / Lightweight Directory Access Protocol / LDAP Injection / Authentication Bypass / Unauthorized Data Access / Data Manipulation / Tautology-Based Injection / Wildcard Injection / Blind LDAP Injection / Boolean Exploitation
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: LDAP Injection Prevention Cheat Sheet

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-90`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # LDAP Injection Prevention Cheat Sheet ## Introduction The Lightweight Directory Access Protocol (LDAP) allows an application to remotely perform operations such as searching and modifying records in directories. LDAP injection results from inadequate input sanitization and vali
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: XPATH injection

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-90`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # XPATH injection ## Basic Syntax An attack technique known as XPath Injection is utilized to take advantage of applications that form XPath (XML Path Language) queries based on user input to query or navigate XML documents. ### Nodes Described Expressions are used to select vari
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: Maddy Mail Server has an LDAP Filter Injection via Unsanitized Username

- **Provenance:** Source: `CYBER_CPT/gh_advisories` | CWE: `CWE-90`
- **Context / Surface:** Source: gh_advisories (en)
- **Root Cause / Analysis:** ### Summary The 'auth.ldap' module constructs LDAP search filters and DN strings by directly interpolating user-supplied usernames via 'strings.ReplaceAll()' without any LDAP filter escaping. An attacker who can reach the SMTP submission (AUTH PLAIN) or IMAP LOGIN interface can i
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 8: xpath injection

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-90`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # xpath injection ## Detection method To find this vulnerabilities sends the string "d'z'0" to every injection point, and searches the response for XPATH errors ### Basic Payloads ' d'z"0 <!--" ' ##### Regexp for error ' System\.Xml\.XPath\.XPathException/MS\.Internal\.Xml/
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
