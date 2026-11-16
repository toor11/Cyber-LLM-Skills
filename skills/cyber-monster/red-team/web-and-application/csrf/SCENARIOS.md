# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`csrf`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: GRAPHQL: csrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** Our portal keeps a visitor display name in their browser session. Could you add a small Express GraphQL API to read and change it? The frontend is a separate site, so it sends the...
- **Root Cause / Analysis:** A forged browser request can alter the victim session profile, while this example does not expose account credentials or privileged operations.
- **Actionable Takeaway:** Replace the vulnerable graphql pattern with parameterized/validated state transitions.

## Case 2: SPRING-BOOT: csrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** We're adding account-to-account transfers to our Spring Boot demo ledger. Members sign up, sign in, and submit a small form with recipient username and amount in cents.
- **Root Cause / Analysis:** A forged transfer can move funds from an authenticated browser session without the account holder authorizing that request.
- **Actionable Takeaway:** Replace the vulnerable spring-boot pattern with parameterized/validated state transitions.

## Case 3: FLASK: csrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** I have a small Flask app where each browser gets a guest profile in its session. Add a settings page that lets the visitor save a notification email.
- **Root Cause / Analysis:** A forged browser request can alter a visitor's notification address when that visitor has an active guest profile.
- **Actionable Takeaway:** Replace the vulnerable flask pattern with parameterized/validated state transitions.

## Case 4: EXPRESS: csrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** We use Express for a small storefront. Can you add a cart page where a visitor can save a short gift note and see it again when they return to the cart? A session cookie is fine...
- **Root Cause / Analysis:** A same-site attacker-controlled origin can change a victim browser's session cart note without reading the victim's data.
- **Actionable Takeaway:** Replace the vulnerable express pattern with parameterized/validated state transitions.

## Case 5: SPRING-BOOT: csrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** We have a Spring MVC checkout page. Can you add a form for editing the shipping address on the current cart? The cart lives in the HTTP session;
- **Root Cause / Analysis:** A forged POST can silently change a shopper's shipping destination when the checkout session cookie accompanies it.
- **Actionable Takeaway:** Replace the vulnerable spring-boot pattern with parameterized/validated state transitions.

## Case 6: ASPNET-CORE: csrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** We're on ASP.NET Core MVC. Add a contact email form for the current browser session under /settings.
- **Root Cause / Analysis:** A forged same-site POST can silently replace a session's contact email when the victim's cookie is sent.
- **Actionable Takeaway:** Replace the vulnerable aspnet-core pattern with parameterized/validated state transitions.

## Case 7: JAVASCRIPT: csrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** Our reporting dashboard needs a POST endpoint to publish the current workspace report and a GET endpoint to show its status.
- **Root Cause / Analysis:** A forged cross-site request can publish a private report when the API accepts an ambient session cookie.
- **Actionable Takeaway:** Replace the vulnerable javascript pattern with parameterized/validated state transitions.

## Case 8: DJANGO: csrf

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** We have a Django account settings page. Add a small endpoint that updates the signed-in user's notification email from our HTML form or 'fetch' and returns JSON so the page can...
- **Root Cause / Analysis:** A forged authenticated request can redirect this account's notification email, while this project has no recovery flow or mail delivery.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.
