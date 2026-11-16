# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`brand-and-impersonation-monitoring`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Queue Filled With Parked Domains

- **Surface & Preconditions:** A registration-keyword alert produces dozens of hits a day and analysts stop reviewing them.
- **Root Cause & Impact:** No content or certificate check was applied, so parked and defensive registrations dominate.
- **Verification & Fix:** Add the content differential and the form-action comparison, order the queue by matched fields, and record parked candidates as deprioritised.

## Case 2: Active Phishing Site Missed

- **Surface & Preconditions:** A candidate serves a copy of the login page but was dismissed because the certificate was issued recently.
- **Root Cause & Impact:** Recent issuance is a signal of activity, not a reason to dismiss; the form action showed the true destination.
- **Verification & Fix:** Compare the form action and page hash against the genuine site, alert on the mismatch, and preserve the screenshot hash for takedown.
