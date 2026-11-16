# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`company-registry-and-beneficial-ownership-osint`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Aggregator Staleness Reported as Ownership

- **Surface & Preconditions:** A shareholder percentage from an aggregator is presented as the current ownership.
- **Root Cause & Impact:** The aggregator had not ingested a recent filing, and the registry shows a different split.
- **Verification & Fix:** Retrieve the registry record directly, cite its date, and present the change with both dates.

## Case 2: Sub-Threshold Holder Recorded as Absent

- **Surface & Preconditions:** A report states that the remaining shares have no owner.
- **Root Cause & Impact:** The registry only discloses above 25%, so the remainder is unknown rather than ownerless.
- **Verification & Fix:** State the threshold, mark the remainder as unknown, and note what additional jurisdiction would be needed to resolve it.
