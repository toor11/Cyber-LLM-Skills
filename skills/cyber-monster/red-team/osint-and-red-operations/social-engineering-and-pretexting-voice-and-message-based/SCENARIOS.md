# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`social-engineering-and-pretexting-voice-and-message-based`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Pressure Script Captures a Real Password

- **Surface & Preconditions:** A tester persuades an agent to read out a temporary password during a lockout scenario.
- **Root Cause & Impact:** The script asked for a credential, which is outside any authorised test.
- **Verification & Fix:** Stop the campaign, ensure the password is rotated, disclose to the client, and rewrite the script to test only the callback step.

## Case 2: Callback Recorded as a Failed Attempt

- **Surface & Preconditions:** An agent insists on calling back, and the report lists the call as unsuccessful.
- **Root Cause & Impact:** The callback is the control working, so the metric is inverted.
- **Verification & Fix:** Recode the outcome as success for the control, and report the callback rate as the effectiveness measure.
