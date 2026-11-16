# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`report-writing-and-findings`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Critical Finding That Nobody Can Reproduce

- **Surface & Preconditions:** A report claims cross-tenant access with no request detail, and the developer cannot reproduce it.
- **Root Cause & Impact:** The finding depended on a state the author created manually and never described.
- **Verification & Fix:** Rewrite with the exact baseline and probe requests, state the precondition, and have a second person run it before resubmitting.

## Case 2: Rating Inflated by an Unstated Precondition

- **Surface & Preconditions:** A finding is rated critical although it requires an administrator session to trigger.
- **Root Cause & Impact:** The impact section omits the precondition, so the reader assumes an unauthenticated attacker.
- **Verification & Fix:** State the precondition explicitly, revise the rating, and keep the technical finding unchanged.
