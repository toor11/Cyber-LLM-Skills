# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`username-and-account-pivot-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Nine Handles, One Person Claimed

- **Surface & Preconditions:** An analyst reports nine accounts as belonging to the subject based on a handle match.
- **Root Cause & Impact:** The handle is common, and no signal beyond the string match was tested.
- **Verification & Fix:** Rank by signal, confirm only the technical match, and deliver the rest as candidates with their evidence.

## Case 2: Deleted Account Recovered From Cache

- **Surface & Preconditions:** A profile page no longer exists, and its cached copy is offered as current evidence.
- **Root Cause & Impact:** The cache describes an earlier date and may predate a change of ownership.
- **Verification & Fix:** Cite the snapshot date, mark the observation as historical, and check for a live account before drawing conclusions.
