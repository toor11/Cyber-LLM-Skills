# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`django-security-patterns`](SKILL.md) | Family: **Application Security**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: DJANGO: debug mode enabled by default

- **Provenance:** Source: `securecode-web` | CWE: `CWE-489`
- **Context / Surface:** We've got a small Django service (5.2, Python 3.12) that serves our product catalog as JSON: '/api/products/' and '/api/products//'.
- **Root Cause / Analysis:** Missing security invariant for CWE-489.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 2: DJANGO: debug mode exposure

- **Provenance:** Source: `securecode-web` | CWE: `CWE-489`
- **Context / Surface:** We are putting a small Django report status service behind our HTTPS reverse proxy. Add GET /healthz/ and GET /reports//;
- **Root Cause / Analysis:** An unauthenticated technical 404 discloses an internal report path and application details, but this example does not demonstrate credential exposure or code execution.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 3: DJANGO: html output encoding

- **Provenance:** Source: `securecode-web` | CWE: `CWE-79`
- **Context / Surface:** Our Django badge preview takes a 'label' query parameter and wraps it in a span. A teammate used 'mark_safe(f'{label}')' so the span survives rendering.
- **Root Cause / Analysis:** An attacker-controlled label can become script-capable HTML in another user's browser, enabling same-origin actions or data access.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 4: DJANGO: template autoescape xss

- **Provenance:** Source: `securecode-web` | CWE: `CWE-79`
- **Context / Surface:** Our Django report preview has customer names and notes. We wrapped the two cells in '{% autoescape off %}' after someone reported that AT&T looked like 'AT&amp;T' in View Source.
- **Root Cause / Analysis:** Unescaped report text can execute script in the report viewer's origin when an attacker controls a displayed value.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 5: DJANGO: json script xss

- **Provenance:** Source: `securecode-web` | CWE: `CWE-79`
- **Context / Surface:** I'm adding a shareable profile preview in Django. Editors will pass a display name and bio in the URL, and the page should bootstrap those fields for the browser to render.
- **Root Cause / Analysis:** A shared preview can execute attacker-chosen JavaScript in the application's origin when a reviewer opens its URL.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 6: DJANGO: csrf get state change

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** In our Django app, add a button on the profile page that switches my profile between public and private. I'd like the URL to be easy to link to from the settings page.
- **Root Cause / Analysis:** A logged-in user's profile visibility can be changed through an attacker-induced top-level navigation, but the effect is limited to this preference.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 7: DJANGO: csrf trusted origin wildcard

- **Provenance:** Source: `securecode-web` | CWE: `CWE-352`
- **Context / Surface:** Our Django API lives at api.example.com and the SPA is at app.example.com. We also have preview subdomains under example.com.
- **Root Cause / Analysis:** Exploitation requires control of a sibling subdomain and can change a signed-in user’s notification email, potentially misrouting future notices.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.

## Case 8: DJANGO: open redirect

- **Provenance:** Source: `securecode-web` | CWE: `CWE-601`
- **Context / Surface:** In our Django app, people often open '/account/' from email and then have to sign in. Can you make login return them to that page? A simple dashboard fallback is fine.
- **Root Cause / Analysis:** An attacker can move a user from a trusted sign-in URL to an external site after login, enabling convincing phishing without directly exposing the session cookie.
- **Actionable Takeaway:** Replace the vulnerable django pattern with parameterized/validated state transitions.
