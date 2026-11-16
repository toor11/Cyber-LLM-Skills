# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`access-control-and-initialization`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Attacker Wins the Initialiser Race

- **Surface & Preconditions:** A proxy is deployed and the initialiser is called in a separate transaction.
- **Root Cause & Impact:** An attacker calls `initialize` first and becomes the owner, gaining every privileged function.
- **Verification & Fix:** Deploy and initialise atomically, disable initialisers on the implementation, and assert both in a test.

## Case 2: Fee Settable Without Bound

- **Surface & Preconditions:** An owner-only fee setter accepts any value.
- **Root Cause & Impact:** The authority is correctly restricted but the resulting value has no limit, so the trusted role can take everything.
- **Verification & Fix:** Add an upper bound to the setter, document the remaining trust assumption, and add a test that an above-cap value reverts.
