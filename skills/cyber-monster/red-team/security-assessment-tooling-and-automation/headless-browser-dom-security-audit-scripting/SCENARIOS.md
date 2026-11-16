# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`headless-browser-dom-security-audit-scripting`](SKILL.md) | Family: **Security Assessment Tooling and Automation**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: CSP Present but Not Enforced

- **Surface & Preconditions:** The response advertises a strict policy, yet an inline handler still executes on the page.
- **Root Cause & Impact:** The policy is delivered as report-only, or a nonce is reused from a cached document, so the header and the behaviour disagree.
- **Verification & Fix:** Load with the violation listener, confirm the disposition field is `report` rather than `enforce`, and report the mode with the header value.

## Case 2: Violation Attributed to the Target

- **Surface & Preconditions:** A violation naming a third-party origin appears during the audit.
- **Root Cause & Impact:** The blocked request originates from a browser extension in the analyst's profile.
- **Verification & Fix:** Re-run in a fresh context with extensions disabled and confirm the blocked URI's initiator before reporting.
