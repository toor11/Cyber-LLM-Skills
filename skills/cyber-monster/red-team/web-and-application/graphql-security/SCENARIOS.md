# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`graphql-security`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Graphql introspection is enabled and leaks details about the schema

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi team ! i've found a misconfiguration in your graphql Api on the endpoint https://www.on-running.com/en-in/graphql in which an attacker is able to run a graphql interospection query to fetch schemas , types , fields , available query operations , after running...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: HTB: Overgraph

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-20`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** The initial web exploitation in Overgraph was really hard. I’ll have to find and chain together a reflective cross site scripting (XSS), a client side template injection (CSTI), and a cross site request forgery (CSRF) to leak an admin’s token. With that token, I can upload videos
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Help

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-20`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Help was an easy box with some neat challenges. As far as I can tell, most people took the unintended route which allowed for skipping the initial section. I’ll either enumerate a GraphQL API to get credentials for a HelpDeskZ instance. I’ll use those creds to exploit an authenti
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: GraphQL NoSQL Injection Through JSON Types

- **Provenance:** Source: `CYBER_CPT/awesome_web_security` | CWE: `CWE-20`
- **Context / Surface:** Source: awesome_web_security (en)
- **Root Cause / Analysis:** # GraphQL NoSQL Injection Through JSON Types One year ago today, I wrote [an article discussing NoSQL Injection and GraphQL] (http://www.east5th.co/blog/2016/06/13/nosql-injection-and-graphql/). I praised [GraphQL] (http://graphql.org/) for eradicating the entire possibility of [No
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: DarkCON Challs

- **Provenance:** Source: `CYBER_CPT/ctftime` | CWE: `CWE-20`
- **Context / Surface:** Source: ctftime (en)
- **Root Cause / Analysis:** # Usage HackTheBox Write-up Let's get started. # Recon We have 2 services HTTP and SSH running on our target 'bash nmap -sV -oA result $IP ' ## Website — Port 80 Okay, let's create a new account. I found this page okay, let's see the admin page. I found a new subdomain so I'l
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: CTF Web - XXE, XML Injection, Command Injection, GraphQL

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-20`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CTF Web - XXE, XML Injection, Command Injection, GraphQL XXE payloads, XML injection, PHP variable-variable tricks, sequential regex bypasses, command injection, and GraphQL exploitation. For core server-side injection (PHP type juggling, file inclusion, SSTI, SSRF), see [serve
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 7: GraphQL Cheat Sheet

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-20`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # GraphQL Cheat Sheet ## Introduction [GraphQL] (https://graphql.org) is an open source query language originally developed by Facebook that can be used to build APIs as an alternative to REST and SOAP. It has gained popularity since its inception in 2012 because of the native fle
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
