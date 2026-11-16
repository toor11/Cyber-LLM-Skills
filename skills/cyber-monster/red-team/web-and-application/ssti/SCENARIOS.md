# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssti`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: H1514 Server Side Template Injection in Return Magic email templates?

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** Possible template injection in return magic email templates. **Description:** I've been playing with return magic workflow email templates and there seems to be some kinda of template injection but I am not sure if it's exploitable or even valid.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Urgent: Server side template injection via Smarty template allows for RCE

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi All, I've found an issue which has allowed me to execute file_get_contents and extract your /etc/passwd file. Description It appears as though you are using smarty on the backend for templating.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: uber.com may RCE by Flask Jinja2 Template Injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, Uber Security Team I found an RCE in rider.uber.com. First, if you change your profile name to {{ '7'*7 }}, and you will receive a mail "Your Uber account information has been updated" sent by support@uber.com And in mail body, you can see your name become '7777777' This is...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Reflected XSS on developer.uber.com via Angular template injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** developer.uber.com is vulnerable to reflected XSS via Angular template injection. The following url demonstrates the root issue using a trivial payload: https://developer.uber.com/docs/deep-linking?q=wrtz{{7*7}} If you view the rendered source of the resulting page, you'll find...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: XSS in $shop$.myshopify.com/admin/ via twine template injection in "Shopify.API.Modal.input" method when

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description The Shopify Embedded App SDK is used to facilitate limited interactions with parent page ('/admin/apps/$id') from an embedded app within the shop admin interface.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: [mercantile.wordpress.org] Reflected XSS via AngularJS Template Injection

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, By injecting a crafted AngularJS payload into the 'search' endpoint on the WordPress Swag Store, it was possible to achieve reflected XSS further to resolved report #221893.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Stored self-XSS in mercantile.wordpress.org checkout

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello Team, **Summary** after i read this #221893 report, i try to find more security issue there, and i was surprise i found an RCE Via Template Injection. Since on that report i see 'ng-bindable' word, its possible the site also effect by RCE. **Step To Reproduce** 1.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Client Side Template Injection (CSTI)

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Client Side Template Injection (CSTI) Summary It is like a [**Server Side Template Injection**] (ssti-server-side-template-injection/index.html) but in the **client**.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.
