# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`prototype-pollution`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: Report Template: Prototype Pollution

- **Provenance:** Source: `bug-bounty-pentest-en`
- **Root Cause / Analysis:** Prototype pollution can lead to XSS, security control bypass, denial of service or remote code execution (server-side Node.js).
- **Actionable Takeaway:** 1. Use Object.create(null) for data objects 2. Validate and filter __proto__, constructor, prototype keys 3. Use Map instead of plain objects for dynamic data 4.

## Case 2: Prototype Pollution leads to XSS on https://blog.swiftype.com/#__proto__[asd]=alert(document.domain)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** deparam function which parses location.hash in https://s.swiftypecdn.com/install/v2/st.js is vulnerable to prototype pollution. There is a script gadget in the same js file which leads to XSS.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: Stored XSS via Mermaid Prototype Pollution vulnerability

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Prologue Gitlab supports Mermaid as part of GFM to allow users to generate diagrams and flowcharts from text. In version 8.6.0, Mermaid added a support of directives to add more controll over styles(themes) applied to the diagrams.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Stored XSS via Mermaid Prototype Pollution vulnerability

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary I am continue investigating #1106238 and found additional vector for prototype pollution and stored xss. Steps to reproduce 1. Create an issue in any repository 2.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Remote Code Execution on Cloud via latest Kibana 7.6.2

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** A prototype pollution in Kibana can be used to gain remote code execution. **Description:** There is a prototype pollution bug in the upgrade assistant's telemetry collector, via a dangerous usage of '_.set':...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: property-expr - Prototype pollution

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I would like to report Prototype pollution in property-expr It allows attacker to modify the prototype of a base object. Module **module name:** property-expr **version:** 2.0.2 **npm page:** 'https://www.npmjs.com/package/property-expr' Module Description > Tiny property path...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Prototype pollution attack (lodash)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I would like to report a prototype pollution vulnerability in lodash. It allows an attacker to inject properties on Object.prototype Module module name: lodash version: 4.17.15 npm page: https://www.npmjs.com/package/lodash Module Description The Lodash library exported as...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: n8n has XML Node Prototype Pollution that to RCE

- **Provenance:** Source: `CYBER_CPT/gh_security_lab`
- **Context / Surface:** CodeQL / Audit Case (en)
- **Root Cause / Analysis:** Impact An authenticated user with permission to create or modify workflows could achieve global prototype pollution via the XML Node leading to RCE when combined with other nodes exploiting the prototype pollution. Patches The issue has been fixed in n8n versions 1.123.32, 2.17.4, and 2.18.1.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.
