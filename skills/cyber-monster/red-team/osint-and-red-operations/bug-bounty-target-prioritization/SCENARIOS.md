# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`bug-bounty-target-prioritization`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Time Spent on an Excluded Class

- **Surface & Preconditions:** A researcher spends a week on rate-limit bypasses that the policy explicitly excludes.
- **Root Cause & Impact:** The exclusion was in the policy text but not in the programme summary page that was read.
- **Verification & Fix:** Extract the policy exclusions with a retrieval date, re-score surfaces, and move effort to a payable band.

## Case 2: New API Version Missed

- **Surface & Preconditions:** Research focuses on v2 paths that have public write-ups, while v3 was deployed two weeks earlier.
- **Root Cause & Impact:** No change signal was collected, so the fresh surface never entered the candidate list.
- **Verification & Fix:** Check release notes and the versioned spec before each block, and record the change signal with its date.
