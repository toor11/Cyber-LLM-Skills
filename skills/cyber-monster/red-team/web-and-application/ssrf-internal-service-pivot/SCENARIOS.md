# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`ssrf-internal-service-pivot`](SKILL.md) | Family: **Web and Application**

Distilled case cards from disclosed reports, CISA KEVs, verified code corpora, and L5 technical analyses.

## Case 1: SQL injection on admin.acronis.host development web service

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** **Summary:** I found an Acronis domain and started hunting on it. During my hunting, I found an admin panel and was able to access this panel (separate report inbound).
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 2: Admin account/panel takeOver and Doing actions in admin panel via DOM-based XSS

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hello team , I found Dom-XSS in your (https://████████/) Webmail Admin Panel that manage attacker to stealing admin sensitive info and doing any action in your webmail admin panel .
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 3: [Admin Panel] CSRF to resume/pause runner

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Hi, Just found a CSRF in admin panel of gitlab instance to pause/resume runner. Steps to reproduce - http://{gitlab_instance}/admin/runners/:runner_id/resume - http://{gitlab_instance}/admin/runners/:runner_id/pause Video: ███████ password: '██████████' Impact Just found a CSRF...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 4: Blind XSS via Feedback form.

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary: Hi Team, I found Blind XSS which is triggered on the admin panel. I was trying to add widgets on the installation page for default theme. When the installation was done, I saw a question like that Are you happy with how everything looks?.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 5: Inject page in admin panel via Shopify.API.pushState

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Summary 'Shopify.API.pushState' call the method 'handleRoutePushEvent', allows you to change routes to open pages from admin panel: js handleRoutePushEvent({pathname: e, search: t, state: a, hash: o}) { const {adminPath: n, history: i} = this.props // 'adminPath' = '/admin' , s...
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 6: Blind XSS - Report review - Admin panel

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Introduction In the Zomato Business app there is the functionality to report a review and give additional details as to why you did report the review.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 7: Inject page in admin panel via Shopify.API.pushState with protocol invalid

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Disclose Token in reports Summary Some time, i found a bug the #662083. Today I found a new payload, invalid protocol are not tested correctly in filter method.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.

## Case 8: Exposed Slinky Instance Admin Panel

- **Provenance:** Source: `hackerone_disclosed_reports`
- **Context / Surface:** Disclosed weakness: Application flaw (severity: reported)
- **Root Cause / Analysis:** Last night the following server went from a 404 to a 200: ███████ Upon navigating to this page, I found that there was a slinky admin panel available here with the ability to change and modify URL redirection.
- **Actionable Takeaway:** Verify authorization, input canonicalization, and state invariants on the affected endpoint.
