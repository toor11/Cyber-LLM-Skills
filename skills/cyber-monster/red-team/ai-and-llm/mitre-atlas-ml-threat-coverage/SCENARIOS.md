# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`mitre-atlas-ml-threat-coverage`](SKILL.md) | Family: **AI and LLM**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Category Marked Covered by a Single Log

- **Surface & Preconditions:** A coverage review marks exfiltration as covered because DLP exists.
- **Root Cause & Impact:** Several techniques in that category produce no DLP event, and the review never distinguishes them.
- **Verification & Fix:** Rewrite the mapping per technique with its observable, verify each telemetry source returns events, and move unsupported techniques to the gap list.

## Case 2: Gap Made Visible Before an Exercise

- **Surface & Preconditions:** A planned test targets a technique whose telemetry is retained for only a day.
- **Root Cause & Impact:** The exercise would produce no evidence, and the gap is a retention decision rather than a detection failure.
- **Verification & Fix:** Record the retention in the gap list, extend it for the exercise window, and re-test with the observable verified.
