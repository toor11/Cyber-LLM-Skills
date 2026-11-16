# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`cross-site-scripting-dom`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: DOM Based XSS in www.hackerone.com via PostMessage

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** The Marketo contact form available on the www.hackerone.com website is affected by a cross-site scripting vulnerability, caused by an insecure 'message' event listener installed on the page.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: DOM Based XSS via postMessage at https://inventory.upserve.com/login/

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description DOM based XSS is possible at https://inventory.upserve.com/login/ due to insecure origin checking when receiving a postMessage. POC 1. Visit https://hq.upserve.com.████████/upserve_xss.html 2. Click link 3.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: DOM Based XSS in www.hackerone.com via PostMessage (bypass of #398054)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary** The security fix by Marketo to resolve the issue reported by @adac95 in #398054 can be bypassed by purchasing an .ma domain for €60.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: DOM XSS at www.forescout.com in Microsoft Edge and IE Browser

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: I've found an DOM Based XSS on homepage Steps To Reproduce: 1.Go to this url and you'll see alert pop 'https://www.forescout.com/#' But this will work just on ME/IE browsers because chrome and firefox have default encode system hash url...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: H1514 DOM XSS on checkout.shopify.com via postMessage handler on /:id/sandbox/google_maps

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description: The '/:id/sandbox/google_maps' and '/:id/sandbox/google_autocomplete' routes on 'checkout.shopify.com' are used to render the Google Map on the "Order Status" page as well as the address prediction on checkout pages.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: DOM based XSS in the WooCommerce plugin

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** I have found a stored DOM based XSS in the order page at WooCommerce 3.5.6. The Data input from HTML element name '_shipping_state' and '_billing_state' in order page outputs data without escaping.When the victim read the page containing the payload, it executes the script.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: DOM Based XSS in Discourse Search

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Steps to Reproduce: 1. Load http://try.discourse.org 2.Now From Top Right Corner Click on Search Button 3. Enter payload their Payload: @prompt(1337)gmail.com 4: Now in new windows that opens click on advance search and The XSS will Occur :) 5: Now copy the link...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: DOM Based XSS in mycrypto.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description & PoC The "connected successfully" message is printed out without any output sanitation: {F271357} This is how it's being printed(this code snippet is taken from mycrypto-master.js, line 4072): {F271359} An attacker can simply put his payload at the link and it'll be...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
