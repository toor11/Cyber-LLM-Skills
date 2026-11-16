# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`http-parameter-pollution-and-mass-assignment`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: HTTP Parameter Pollution using semicolons in iframe element at hackerone.com/careers allows loading exter

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** I noticed that HackerOne career pages loads it's application forms from Greenhouse.io via an iframe. The **gh_jid** parameter value is taken into the iframe element for the token parameter in the iframe URL (boards.greenhouse.io).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Parameter pollution in social sharing buttons

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello! For example we have a link 'https://hackerone.com/blog/introducing-signal-and-impact', and we will change it to 'https://hackerone.com/blog/introducing-signal-and-impact?&u=https://vk.com/durov'.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Cross Site Scripting(XSS) on IRCCloud Badges Page (using Parameter Pollution)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I. Vulnerability --------------------- IRCCloud is affected by Cross Site Scripting vulnerability in its badges page. (www.irccloud.com/badges) II. Description --------------------- IRCCloud is open to parameter pollution attacks ie.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Object injection in 'stripe-billing-typographic' GitHub project via /auth/login

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: It is possible to use an object injection failure to achieve a sql injection, where attacker uses the means to bypass authentication, requiring only a valid password within the database.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: WordPress < 5.8.3 - Object Injection Vulnerability / Sonar

- **Provenance:** Source: `CYBER_CPT/govuln`
- **Context / Surface:** Go Vulnerability Advisory (None)
- **Root Cause / Analysis:** ___ Products Why Sonar Pricing Developers Resources Company 3 Start for free BLOG POST WordPress < 5.8.3 - Object Injection Vulnerability February 8, 2022 Simon Scannell VULNERABILITY RESEARCHER TL;DR overview A WordPress object injection vulnerability allows attackers to instantiate arbitrary PHP...
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 6: Mass Assignment (CWE-915) – Privilege Escalation via Unsafe Model Binding

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-915`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Mass Assignment (CWE-915) – Privilege Escalation via Unsafe Model Binding Mass assignment (a.k.a. insecure object binding) happens when an API/controller takes user-supplied JSON and directly binds it to a server-side model/entity without an explicit allow-list of fields.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 7: Hack The Box — Tenet Writeup

- **Provenance:** Source: `CYBER_CPT/L5/ctf_search`
- **Context / Surface:** High-depth analysis (ctf_search, edu=4)
- **Root Cause / Analysis:** Hack The Box — Tenet Writeup > TL;DR A comment in the blog’s Migration part leads you to an endpoint that is vulnerable to PHP Object Injection. After successfully injecting a malicious object and obtaining a shell, you can escalate to the user by reusing the MYSQL credentials found in the WordPress config file.
- **Actionable Takeaway:** Validate root-cause preconditions and apply defense-in-depth controls.

## Case 8: Parameter Pollution / JSON Injection

- **Provenance:** Source: `CYBER_CPT/hacktricks` | CWE: `CWE-235`
- **Context / Surface:** Source: hacktricks (en)
- **Root Cause / Analysis:** # Parameter Pollution / JSON Injection ## HTTP Parameter Pollution (HPP) Overview HTTP Parameter Pollution (HPP) is a technique where attackers manipulate HTTP parameters to change the behavior of a web application in unintended ways. This manipulation is done by adding, modifyin
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
