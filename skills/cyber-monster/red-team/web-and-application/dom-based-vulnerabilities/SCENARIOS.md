# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`dom-based-vulnerabilities`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: DOM Based XSS via postMessage at https://inventory.upserve.com/login/

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description DOM based XSS is possible at https://inventory.upserve.com/login/ due to insecure origin checking when receiving a postMessage. POC 1. Visit https://hq.upserve.com.████████/upserve_xss.html 2. Click link 3.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: DOM Based XSS in www.hackerone.com via PostMessage (bypass of #398054)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary** The security fix by Marketo to resolve the issue reported by @adac95 in #398054 can be bypassed by purchasing an .ma domain for €60.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: DOM XSS at www.forescout.com in Microsoft Edge and IE Browser

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: I've found an DOM Based XSS on homepage Steps To Reproduce: 1.Go to this url and you'll see alert pop 'https://www.forescout.com/#' But this will work just on ME/IE browsers because chrome and firefox have default encode system hash url...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: H1514 DOM XSS on checkout.shopify.com via postMessage handler on /:id/sandbox/google_maps

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Description: The '/:id/sandbox/google_maps' and '/:id/sandbox/google_autocomplete' routes on 'checkout.shopify.com' are used to render the Google Map on the "Order Status" page as well as the address prediction on checkout pages.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: DOM Based XSS In mercantile.wordpress.org

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello, There is a DOM XSS in mercantile.wordpress.org in the apparel subcat. For example: https://mercantile.wordpress.org/product-category/apparel/?subcat= Steps To Reproduce 1. Go to https://mercantile.wordpress.org 2. Click on apparel 3.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Dom Based Xss DIV.innerHTML parameters store.starbucks*

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi! this subdomain store.starbucks* vulnerable to dom based xss. you are using the vulnerable library jQuery.V1_10_1 parameters location.hash DIV.innerHTML .
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Dom Clobbering

- **Provenance:** Source: `CYBER_CPT/hacktricks`
- **Context / Surface:** Security Assessment Guide (en)
- **Root Cause / Analysis:** Dom Clobbering **Basics** It's possible to generate **global variables inside the JS context** with the attributes **'id'** and **'name'** in HTML tags.
- **Actionable Takeaway:** Cross-check preconditions and telemetry before applying to the target.

## Case 8: The DOMino Effect Automated Detection and Exploitation of DOM Clobbering Vulnerability at Scale

- **Provenance:** Source: `CYBER_CPT/infocon` | CWE: `CWE-79`
- **Context / Surface:** Source: infocon (en)
- **Root Cause / Analysis:** # The DOMino Effect: Automated Detection and Exploitation of DOM Clobbering Vulnerability at Scale Zhengyu Liu & Jianjia Yu SecLab @ Johns Hopkins University Joint work with Theo (Ishmeal) Lee, Zifeng Kang, and Yinzhi Cao. ## 0x01 / Introduction to DOM Clobbering ### How the Stor
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
