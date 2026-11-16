# Structured Case Cards and Real-World Scenarios

> Sub-skill: [`smart-contract-audit`](SKILL.md) | Family: **Blockchain**

Two worked shapes for this technique. Identifiers are placeholders for the engagement's own assets; no incident below is a fabricated advisory.

## Case 1: Missing Authorisation on a Sweep Function

- **Surface & Preconditions:** A contract exposes a sweep that transfers the full balance to the owner address but never checks the caller.
- **Root Cause & Impact:** Any caller can trigger the transfer; the funds go to the owner but the protocol's solvency invariant is broken mid-block.
- **Verification & Fix:** Add the caller check, write a test asserting a non-owner call reverts, and confirm the invariant test still passes.

## Case 2: Initialiser Left Callable on an Implementation

- **Surface & Preconditions:** A proxy pattern deploys the implementation without calling `initialize`, leaving it open.
- **Root Cause & Impact:** An attacker initialises the implementation and becomes its owner, which matters wherever the implementation holds approvals or is delegatecalled.
- **Verification & Fix:** Initialise atomically in the deployment script, add `_disableInitializers()` in the implementation constructor, and assert the initialiser reverts afterwards.
