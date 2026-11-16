# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`social-engineering-and-pretexting`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Approval Missing for an Impersonated Vendor

- **Surface & Preconditions:** The scenario requires calling as a named software vendor's support desk.
- **Root Cause & Impact:** The authorisation covered internal roles only, so impersonating an external party was not approved.
- **Verification & Fix:** Stop the scenario, obtain written approval naming the vendor, and re-run only after the authorisation is amended.

## Case 2: Debrief Skipped After a Successful Test

- **Surface & Preconditions:** An agent disclosed information during the pretext and was never told the call was a test.
- **Root Cause & Impact:** The contact log existed but the debrief register was not maintained.
- **Verification & Fix:** Contact the agent and their lead, record the debrief, and add a blocking check that prevents closing an exercise with undebriefed contacts.
