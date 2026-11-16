# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`osint-methodology-collection-and-logging`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Observation Table Missing Analysts

- **Surface & Preconditions:** A shared collection database has rows with no analyst attribution, and two entries conflict.
- **Root Cause & Impact:** Nobody can determine who collected the conflicting records or with what query.
- **Verification & Fix:** Add the analyst column to the write path, re-collect the conflicting records, and mark the unattributed rows as unusable.

## Case 2: Source Changed Between Briefings

- **Surface & Preconditions:** A registrant field differs from the value cited in last week's briefing.
- **Root Cause & Impact:** The collector overwrote the row instead of appending, so the earlier value is gone.
- **Verification & Fix:** Restore append-only writes, retrieve both hashes if the archive holds them, and state the change as a finding with both timestamps.
