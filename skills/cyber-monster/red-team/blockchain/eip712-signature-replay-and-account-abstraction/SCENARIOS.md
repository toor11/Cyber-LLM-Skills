# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`eip712-signature-replay-and-account-abstraction`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Relayer Redirects the Transfer

- **Surface & Preconditions:** A forwarder signature covers the amount but not the recipient.
- **Root Cause & Impact:** The relayer supplies their own address as `to` and the signature remains valid.
- **Verification & Fix:** Include the recipient in the typed struct, add a test that a changed recipient fails verification, and check every relayer-supplied field the same way.

## Case 2: 7702 Account Initialised by an Attacker

- **Surface & Preconditions:** A delegated EOA initialises its account in a second transaction after the delegation lands.
- **Root Cause & Impact:** An attacker calls the initialiser first and sets themselves as owner.
- **Verification & Fix:** Require `msg.sender == address(this)` and single-use initialisation, perform delegation and initialisation atomically, and test that an external caller's initialise reverts.
