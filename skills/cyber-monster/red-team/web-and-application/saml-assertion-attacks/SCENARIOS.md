# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`saml-assertion-attacks`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: How to Hunt Bugs in SAML; a Methodology - Part I

- **Provenance:** Source: `CYBER_CPT/awesome_web_security` | CWE: `CWE-347`
- **Context / Surface:** Source: awesome_web_security (en)
- **Root Cause / Analysis:** # How to Hunt Bugs in SAML; a Methodology - Part I ## Security Assertion Markup Language (SAML) ## SAML by Example; an Analogy ## SAML Authentication Workflow ## SAML Request Example ## SAML Response Example ## Enveloped Signature ## Enveloping Signature ## Detached Signature Thi
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 2: How to Hunt Bugs in SAML; a Methodology - Part II

- **Provenance:** Source: `CYBER_CPT/awesome_web_security` | CWE: `CWE-347`
- **Context / Surface:** Source: awesome_web_security (en)
- **Root Cause / Analysis:** # How to Hunt Bugs in SAML; a Methodology - Part II This post is the second in a series about How to Hunt Bugs in Security Assertion Markup Language (SAML). This post examines SAML vulnerabilities as well as how to test for those vulnerabilities using [SAML Raider] (https://github
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 3: HTB: Barrier

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-347`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Barrier is a Linux box with GitLab, Authentik, and Apache Guacamole. I’ll exploit a SAML signature bypass vulnerability in GitLab’s Ruby SAML library to forge a SAML assertion and log in as admin. From GitLab’s CI/CD variables, I’ll recover an Authentik API token and use it to cr
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 4: HTB: Cerberus

- **Provenance:** Source: `CYBER_CPT/oxdf` | CWE: `CWE-347`
- **Context / Surface:** Source: oxdf (en)
- **Root Cause / Analysis:** Cerberus is unique in that it’s one of the few boxes on HTB (or any CTF) that has Windows hosting a Linux VM. To start, I can only access an IcingaWeb2 instance running in the VM. I’ll exploit two CVEs in Icinga, first with file read to get credentials, and then a file write to w
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 5: SAML Security Cheat Sheet

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-347`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # SAML Security Cheat Sheet ## Introduction The **S**ecurity **A**ssertion **M**arkup **L**anguage ([SAML] (https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language)) is an open standard for exchanging authorization and authentication information. The *Web Browser SAML/SSO
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.

## Case 6: CTF Web - OAuth, SAML & Infrastructure Auth Attacks

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-347`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CTF Web - OAuth, SAML & Infrastructure Auth Attacks ## OAuth/OIDC Exploitation ### Open Redirect Token Theft 'python # OAuth authorization with redirect_uri manipulation # If redirect_uri validation is weak, steal tokens via open redirect import requests # Step 1: Craft malic
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
