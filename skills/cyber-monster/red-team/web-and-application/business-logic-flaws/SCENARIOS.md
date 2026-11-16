# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`business-logic-flaws`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: EXPRESS: checkout input validation

- **Provenance:** Source: `securecode-web` | CWE: `CWE-20`
- **Context / Surface:** We have an Express checkout API. Add 'POST /orders' for one catalog product and quantity so the cart page can show the order amount. Use 'mug-1' at $25.00 as sample catalog data.
- **Root Cause / Analysis:** A caller can set an order total below the catalog price or create a negative total, risking direct revenue loss if downstream checkout trusts it.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 2: An attacker can buy marketplace articles for lower prices as it allows for negative quantity values leadi

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi there, When we **Summary:** When someone goes to https://www.semrush.com/marketplace/offers/ and orders for articles, an attacker can pay for less than intended due to negative quantities being allowed.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: OLO Total price manipulation using negative quantities

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Manipulating an order request JSON object, containing an additional item with a negative quantity directly manipulates the total amount of the order. In the following JSON request, an order is submitted for 2 ChickenBurgers ($12 each), as well as -1 BreadPuddings ($9 each).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: IDOR vulnerability (Price manipulation)

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Target: acronis.cz Step to Reproduce 1.Go to acronis.cz 2.buy any product in this case i am going to buy this https://www.acronis.cz/produkt/acronis-cyber-protect-home-office/ for test 3.fill up details 4.go to burpsuite turn on intercept 5.click on buy now 6.check request in...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Using GitLab to monitor and hijack domains in mass quantity.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Vulnerability Description There is a logic flaw in how GitLab pages can set custom domains that allows an attacker to actively monitor domains and hijack them as soon as they point to '52.167.214.135'. GitLab allows setting an unlimited number of domains for a single repository.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: (Possible) staff account takeover via reset token bruteforce at helpdesk.bistudio.com

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** As stated in a brief exchange with @rvn in my other report ##312433, I might have found a logic flaw in the way https://helpdesk.bistudio.com handles the reset flow and tokens.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Business Logic Flaw - A non premium user can change/update retailers to get cashback on all the retailers

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, While testing your android application I've found a business logic flaw by using which a non premium user can update/change the retailers when ever and what ever retailers he wants to. Curve application has a functionality called "Earn curve cash".
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: CVE-2021-38000: Chrome Intents Logic Flaw

- **Provenance:** Source: `CYBER_CPT/github_security_md` | CWE: `CWE-840`
- **Context / Surface:** Source: github_security_md (en)
- **Root Cause / Analysis:** # CVE-2021-38000: Chrome Intents Logic Flaw *Maddie Stone, Google Project Zero* ## The Basics **Disclosure or Patch Date:** October 28, 2021 **Product:** Google Chrome **Advisory:** https://chromereleases.googleblog.com/2021/10/stable-channel-update-for-desktop_28.html **Affected
- **Actionable Takeaway:** Confirm entry-point preconditions and verify remediation controls.
