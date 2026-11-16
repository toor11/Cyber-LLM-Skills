# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`osint-identity-and-email-correlation`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Handle Match Reported as Identity

- **Surface & Preconditions:** A report states that a forum account belongs to a named employee because the handle matches.
- **Root Cause & Impact:** The handle is a common word and appears on unrelated accounts; no second signal was tested.
- **Verification & Fix:** Record the forum account as a candidate, test for a key or commit match, and only promote it if an identifier matches.

## Case 2: Signed Commit Confirms the Anchor

- **Surface & Preconditions:** A code host shows commits authored by the anchor email and signed by a key whose fingerprint matches the keyserver entry.
- **Root Cause & Impact:** The signature ties the commit to the key, and the key to the address, giving a confirmed link.
- **Verification & Fix:** Record both signals with their sources and dates, and mark the link confirmed in the correlation table.
