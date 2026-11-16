# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`osint-operational-security`](SKILL.md) | Family: **OSINT and Red Operations**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Target Sees the Client's Address

- **Surface & Preconditions:** A collection script queries the target's public API from the office network.
- **Root Cause & Impact:** The target's logs now show the client's address researching its own infrastructure, and the engagement is compromised.
- **Verification & Fix:** Move collection to the designated egress, record the observed address per source, and disclose the exposure to the client.

## Case 2: Persona Left Active After Close-out

- **Surface & Preconditions:** A research account created for the engagement still has an active session months later.
- **Root Cause & Impact:** The persona register had no retirement step, so nothing prompted closure.
- **Verification & Fix:** Add a retirement date at creation, close the account at engagement end, and record the closure in the register.
