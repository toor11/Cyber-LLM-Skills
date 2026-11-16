# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`red-team-operations-and-scoping`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Excluded System Touched

- **Surface & Preconditions:** An assessment sends traffic to an address inside the in-scope range that belongs to a third-party payment gateway.
- **Root Cause & Impact:** The exclusions list existed but the action did not check it, and the range membership test alone passed.
- **Verification & Fix:** Add the exclusion check to the scope gate, re-run with the gate in place, and disclose the contact to the client with the action log.

## Case 2: Assessment Mistaken for an Intrusion

- **Surface & Preconditions:** The SOC declares an incident during the exercise because the engagement was not deconflicted.
- **Root Cause & Impact:** No contact or observable marker was recorded, so the defenders had no way to identify the traffic.
- **Verification & Fix:** Add the deconfliction contact and marker, announce the window, and include the marker in every request's user-agent.
