# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`social-engineering-and-pretexting-email-and-credential-phishing`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Credential Capture in an Awareness Exercise

- **Surface & Preconditions:** A campaign landing page stores submitted usernames and passwords for reporting.
- **Root Cause & Impact:** The stored values are real credentials, so the exercise created the incident it was meant to prevent.
- **Verification & Fix:** Delete the captured data, disclose to the client, reconfigure the landing page to discard request bodies, and re-run with event-only logging.

## Case 2: Click Rate Reported as the Finding

- **Surface & Preconditions:** The report leads with a click rate and says nothing about the verification process.
- **Root Cause & Impact:** Clicks measure exposure, not control failure, and give the client no remediation target.
- **Verification & Fix:** Rebaseline on the documented verification step, report the proportion of recipients who skipped it, and attach the process remediation.
